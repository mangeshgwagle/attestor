; ---------------------------------------------------------------------------
; chainforge_kernel_x86_64.asm -- ChainForge 4.2 fixed-point kernels
; Target: x86-64, System V AMD64 ABI. Documentation-grade reviewed artifact
; in the mc_asm style: shipped for static review and structural verification;
; NEVER loaded or executed by the Attestor analysis path.
;
; The linear equations implemented here mirror detector/chainforge42.py:
;
;   (1) Chain scoring (linear form over five features):
;         score(c) = SUM_{i=0..4} w[i] * f[i](c),     w in Q16 fixed point
;
;   (2) Centrality iteration step (linear system solved by repeated axpy):
;         x'[j] = ALPHA * SUM_i x[i]*M[j][i] + (1 - ALPHA)*s[j]
;       implemented as repeated saxpy over row j of M.
;
; Registers per System V: args in rdi, rsi, rdx, rcx; return in rax.
; ---------------------------------------------------------------------------

section .rodata
align 8
global WEIGHTS_Q16
WEIGHTS_Q16:
    dq 22938                       ; impact_reach          0.35 * 2^16
    dq 16384                       ; auth_bypass_density   0.25 * 2^16
    dq 13107                       ; severity_mass         0.20 * 2^16
    dq 6554                        ; brevity               0.10 * 2^16
    dq 6554                        ; novelty               0.10 * 2^16

global ALPHA_Q16
ALPHA_Q16:
    dq 55706                       ; alpha                 0.85 * 2^16

section .text

; ---------------------------------------------------------------------------
; uint64_t dot5_q16(const uint64_t *weights, const uint64_t *features)
;   rdi = weights pointer, rsi = features pointer
;   returns rax = (SUM w[i]*f[i]) >> 16      (arithmetic shift, fixed point)
; ---------------------------------------------------------------------------
global dot5_q16
dot5_q16:
    xor     rax, rax                ; accumulator = 0
    xor     rcx, rcx                ; index i = 0
.acc_loop:
    mov     rdx, [rdi + rcx*8]      ; rdx = w[i]
    imul    rdx, [rsi + rcx*8]      ; rdx = w[i] * f[i]
    add     rax, rdx                ; acc += term            (the SUM)
    inc     rcx
    cmp     rcx, 5
    jl      .acc_loop
    sar     rax, 16                 ; fixed-point rescale (>> 2^16 shift)
    ret

; ---------------------------------------------------------------------------
; void saxpy_q16(uint64_t *y, const uint64_t *x, uint64_t a, uint64_t n)
;   rdi = y, rsi = x, rdx = a (scaled scalar), rcx = n
;   y[i] += a * x[i]  -- one power-iteration row update
; ---------------------------------------------------------------------------
global saxpy_q16
saxpy_q16:
.test_loop:
    test    rcx, rcx
    jz      .done
    mov     rax, [rsi]              ; rax = x[i]
    imul    rax, rdx                ; rax = a * x[i]
    add     [rdi], rax              ; y[i] += rax
    lea     rdi, [rdi + 8]
    lea     rsi, [rsi + 8]
    dec     rcx
    jmp     .test_loop
.done:
    ret

; ---------------------------------------------------------------------------
; uint64_t blend_seed(uint64_t acc, uint64_t s, uint64_t one_minus_alpha)
;   acc' = acc + one_minus_alpha * s / 65536
;   completes x' = ALPHA*(...) + (1-ALPHA)*s
; ---------------------------------------------------------------------------
global blend_seed
blend_seed:
    mov     rax, rdx                ; one_minus_alpha
    imul    rax, rsi                ; * s
    sar     rax, 16                 ; / 2^16
    add     rax, rdi                ; + acc
    ret
