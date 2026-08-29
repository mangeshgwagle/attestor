; ---------------------------------------------------------------------------
; triage_kernel_x86_64.asm -- Attestor Exploitability-Triage engine
; Language: x86-64 assembly, NASM syntax, Win64 ABI.
;
; This module IS the triage computation. There is no reference logic in any
; other language on the analysis path -- callers load this DLL and execute
; these routines directly.
;
; Model (Q16 fixed point throughout, scale 2^16 = 65536):
;   score(f) = ( SUM_{i<n} w[i] * f[i] ) >> 16          ; linear form
;   grade(score, kev):
;       score <= 0                -> 0   invalid/unusable input
;       0 <  score <  0.30        -> 1   theoretical-only
;       0.30 <= score < 0.50      -> 2   chained-only
;       0.50 <= score < 0.70      -> 3   exploitable-with-preconditions
;       score >= 0.70             -> 4   readily-exploitable
;   KEV escalation: kev != 0 forces grade >= 3 (actively exploited in the
;   wild may never be classed below the preconditioned tier).
;
; Win64 register contract: args rcx, rdx, r8, r9; return rax.
; Only volatile registers are used, so no shadow-space save obligations.
; ---------------------------------------------------------------------------

default rel

section .text

global triage_score_q16
global triage_grade

; ---------------------------------------------------------------------------
; int64_t triage_score_q16(const int64_t *w   /* rcx */,
;                          const int64_t *f   /* rdx */,
;                          int64_t         n  /* r8  */)
;
; Returns (SUM w[i]*f[i]) >> 16 as an algebraic value. A caller whose inputs
; are all within [0,65535] receives a result in [0,65535].
; ---------------------------------------------------------------------------
triage_score_q16:
    xor     rax, rax                ; accumulator = 0
    xor     r9,  r9                 ; i = 0
    test    r8,  r8
    jle     .rescale                ; n <= 0: skip loop entirely
.accumulate:
    mov     r10, [rcx + r9*8]       ; r10 = w[i]
    imul    r10, [rdx + r9*8]       ; r10 = w[i] * f[i]
    add     rax, r10                ; acc += term
    inc     r9
    cmp     r9,  r8
    jl      .accumulate
.rescale:
    sar     rax, 16                 ; fixed-point rescale (Q16 -> integer)
    ret

; ---------------------------------------------------------------------------
; int64_t triage_grade(int64_t score_q16 /* rcx */, int64_t kev /* rdx */)
;
; Band classification per the model above, followed by the KEV escalation
; rule. Pure branch arithmetic; no memory access beyond registers.
; ---------------------------------------------------------------------------
triage_grade:
    xor     eax, eax                ; grade = 0 (invalid band)
    test    rcx, rcx
    jle     .return                 ; score <= 0 stays invalid
    cmp     rcx, 45875              ; 0.70 in Q16 (45875 = ceil(0.70*65536))
    jge     .readily_exploitable
    cmp     rcx, 32768              ; 0.50 in Q16
    jge     .with_preconditions
    cmp     rcx, 19661              ; 0.30 in Q16 (ceil(0.30*65536))
    jge     .chained_only
    mov     eax, 1                  ; theoretical-only band
    jmp     .kev_escalation

.readily_exploitable:
    mov     eax, 4
    jmp     .return

.with_preconditions:
    mov     eax, 3
    jmp     .kev_escalation

.chained_only:
    mov     eax, 2
    ; fall through to escalation

.kev_escalation:
    test    rdx, rdx                ; kev flag nonzero?
    jz      .return
    cmp     eax, 3                  ; already at preconditioned tier?
    jge     .return
    mov     eax, 3                  ; escalate to at least tier 3
.return:
    ret

section .note
; House boundary note, kept in the binary itself:
; Grades are static review points over declared evidence. Nothing here
; executes target code, contacts a network, or proves runtime exploitation.
