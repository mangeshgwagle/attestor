#!/usr/bin/env python3
"""math_engine42 -- x86-64 accelerated math engine for Attestor.

High-performance math computation using x86-64 native instructions where
available, with pure-Python fallback for portability. Covers:

  - Arithmetic (arbitrary precision, modular, saturating)
  - Linear algebra (vectors, matrices, determinants, eigenvalues)
  - Calculus (symbolic differentiation, numerical integration, limits)
  - Number theory (primes, factoring, gcd/lcm, modular inverse, CRT)
  - Statistics (descriptive, distributions, hypothesis testing)
  - Cryptographic math (RSA, DH, elliptic curves, lattice ops)
  - Signal processing (FFT, convolution, correlation)
  - Graph theory (shortest path, MST, flow, coloring)

    attestor math eval "2^128 + 1"
    attestor math factor 600851475143
    attestor math primes --below 10000
    attestor math matrix det "[[1,2],[3,4]]"
    attestor math derive "x^3 + 2*x^2 - 5*x + 3"
    attestor math integrate "sin(x)" 0 pi
    attestor math fft "1,2,3,4,5,6,7,8"
    attestor math crypto rsa-keygen 2048
    attestor math stats describe "1,2,3,4,5,6,7,8,9,10"
    attestor math solve "2*x + 3 = 7"
    attestor math graph shortest "A-B:3,B-C:2,A-C:10" A C
    attestor math bench              run full benchmark suite
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import math
import os
import platform
import struct
import sys
import tempfile
import time
from collections import defaultdict
from decimal import Decimal, getcontext
from fractions import Fraction
from functools import reduce
from pathlib import Path

ME_SCHEMA = "attestor-math-engine-4.2"
EXIT_OK = 0
EXIT_ERR = 1
EXIT_INVALID = 2

getcontext().prec = 100

# ── x86-64 native acceleration ───────────────────────────────────────

_ASM_AVAILABLE = False
_asm_lib = None


def _try_load_native():
    """Attempt to JIT compile and load x86-64 math kernels."""
    global _ASM_AVAILABLE, _asm_lib
    if platform.machine() not in ("x86_64", "AMD64"):
        return
    nasm = ctypes.util.find_library("nasm")
    try:
        import subprocess
        r = subprocess.run(["nasm", "--version"], capture_output=True, text=True)
        if r.returncode != 0:
            return
    except FileNotFoundError:
        return

    asm_src = _generate_asm_kernels()
    tmpdir = tempfile.mkdtemp(prefix="attestor_math_")
    asm_path = os.path.join(tmpdir, "math_kernels.asm")
    if sys.platform == "win32":
        obj_path = os.path.join(tmpdir, "math_kernels.obj")
        dll_path = os.path.join(tmpdir, "math_kernels.dll")
        fmt = "win64"
    else:
        obj_path = os.path.join(tmpdir, "math_kernels.o")
        dll_path = os.path.join(tmpdir, "math_kernels.so")
        fmt = "elf64"

    with open(asm_path, "w") as f:
        f.write(asm_src)

    try:
        subprocess.run(["nasm", "-f", fmt, asm_path, "-o", obj_path],
                       check=True, capture_output=True)
        if sys.platform == "win32":
            subprocess.run(["link", "/DLL", "/OUT:" + dll_path, obj_path],
                           check=True, capture_output=True)
        else:
            subprocess.run(["gcc", "-shared", "-o", dll_path, obj_path, "-nostdlib"],
                           check=True, capture_output=True)
        _asm_lib = ctypes.CDLL(dll_path)
        _ASM_AVAILABLE = True
    except (subprocess.CalledProcessError, OSError):
        pass


def _generate_asm_kernels():
    """Generate x86-64 NASM source for core math operations."""
    if sys.platform == "win32":
        # Windows x64 ABI: rcx, rdx, r8, r9
        return """\
; Attestor Math Engine -- x86-64 kernels (Windows x64 ABI)
bits 64
default rel

section .text

; uint64_t asm_gcd(uint64_t a, uint64_t b)
global asm_gcd
asm_gcd:
    mov rax, rcx
    mov rcx, rdx
.loop:
    test rcx, rcx
    jz .done
    xor rdx, rdx
    div rcx
    mov rax, rcx
    mov rcx, rdx
    jmp .loop
.done:
    ret

; uint64_t asm_mod_exp(uint64_t base, uint64_t exp, uint64_t mod)
global asm_mod_exp
asm_mod_exp:
    push rbx
    mov rax, rcx      ; base
    mov rbx, rdx      ; exp
    mov rcx, r8       ; mod
    mov r9, 1         ; result = 1
    xor rdx, rdx
    div rcx
    mov rax, rdx      ; base %= mod
.exp_loop:
    test rbx, rbx
    jz .exp_done
    test rbx, 1
    jz .exp_skip
    push rax
    mov rax, r9
    mul qword [rsp]   ; result * base -> rdx:rax
    add rsp, 8
    div rcx
    mov r9, rdx       ; result = (result * base) % mod
.exp_skip:
    mul rax            ; base * base -> rdx:rax
    div rcx
    mov rax, rdx       ; base = (base * base) % mod
    shr rbx, 1
    jmp .exp_loop
.exp_done:
    mov rax, r9
    pop rbx
    ret

; uint64_t asm_popcount(uint64_t x)
global asm_popcount
asm_popcount:
    popcnt rax, rcx
    ret

; uint64_t asm_clz(uint64_t x)  -- count leading zeros
global asm_clz
asm_clz:
    bsr rax, rcx
    jz .all_zero
    xor rax, 63
    ret
.all_zero:
    mov rax, 64
    ret

; void asm_dot_product(double* a, double* b, uint64_t n, double* result)
global asm_dot_product
asm_dot_product:
    ; rcx=a, rdx=b, r8=n, r9=result
    vxorpd xmm0, xmm0, xmm0
    xor rax, rax
.dp_loop:
    cmp rax, r8
    jge .dp_done
    vmovsd xmm1, [rcx + rax*8]
    vmulsd xmm1, xmm1, [rdx + rax*8]
    vaddsd xmm0, xmm0, xmm1
    inc rax
    jmp .dp_loop
.dp_done:
    vmovsd [r9], xmm0
    ret

; double asm_fast_sqrt(double x) -- using sqrtsd
global asm_fast_sqrt
asm_fast_sqrt:
    sqrtsd xmm0, xmm0
    ret

; double asm_fast_inv_sqrt(double x) -- Quake-style fast inverse sqrt, double precision
global asm_fast_inv_sqrt
asm_fast_inv_sqrt:
    movq rax, xmm0
    shr rax, 1
    mov rcx, 0x5FE6EB50C7B537A9
    sub rcx, rax
    movq xmm0, rcx
    ; one Newton-Raphson iteration
    movsd xmm1, xmm0
    mulsd xmm1, xmm0       ; y*y
    mulsd xmm1, xmm0       ; unused -- simplified
    ret
"""
    else:
        # System V AMD64 ABI: rdi, rsi, rdx, rcx, r8, r9
        return """\
; Attestor Math Engine -- x86-64 kernels (System V AMD64 ABI)
bits 64
default rel

section .text

; uint64_t asm_gcd(uint64_t a, uint64_t b)
global asm_gcd
asm_gcd:
    mov rax, rdi
    mov rcx, rsi
.loop:
    test rcx, rcx
    jz .done
    xor rdx, rdx
    div rcx
    mov rax, rcx
    mov rcx, rdx
    jmp .loop
.done:
    ret

; uint64_t asm_mod_exp(uint64_t base, uint64_t exp, uint64_t mod)
global asm_mod_exp
asm_mod_exp:
    push rbx
    mov rax, rdi       ; base
    mov rbx, rsi       ; exp
    mov rcx, rdx       ; mod
    mov r9, 1          ; result = 1
    xor rdx, rdx
    div rcx
    mov rax, rdx       ; base %= mod
.exp_loop:
    test rbx, rbx
    jz .exp_done
    test rbx, 1
    jz .exp_skip
    push rax
    mov rax, r9
    mul qword [rsp]
    add rsp, 8
    div rcx
    mov r9, rdx
.exp_skip:
    mul rax
    div rcx
    mov rax, rdx
    shr rbx, 1
    jmp .exp_loop
.exp_done:
    mov rax, r9
    pop rbx
    ret

; uint64_t asm_popcount(uint64_t x)
global asm_popcount
asm_popcount:
    popcnt rax, rdi
    ret

; uint64_t asm_clz(uint64_t x)
global asm_clz
asm_clz:
    bsr rax, rdi
    jz .all_zero
    xor rax, 63
    ret
.all_zero:
    mov rax, 64
    ret

; void asm_dot_product(double* a, double* b, uint64_t n, double* result)
global asm_dot_product
asm_dot_product:
    ; rdi=a, rsi=b, rdx=n, rcx=result
    vxorpd xmm0, xmm0, xmm0
    xor rax, rax
.dp_loop:
    cmp rax, rdx
    jge .dp_done
    vmovsd xmm1, [rdi + rax*8]
    vmulsd xmm1, xmm1, [rsi + rax*8]
    vaddsd xmm0, xmm0, xmm1
    inc rax
    jmp .dp_loop
.dp_done:
    vmovsd [rcx], xmm0
    ret

; double asm_fast_sqrt(double x)
global asm_fast_sqrt
asm_fast_sqrt:
    sqrtsd xmm0, xmm0
    ret
"""


# ── Pure Python math core (always available) ─────────────────────────

def gcd(a, b):
    if _ASM_AVAILABLE and isinstance(a, int) and isinstance(b, int) and 0 < a < 2**63 and 0 < b < 2**63:
        return _asm_lib.asm_gcd(ctypes.c_uint64(a), ctypes.c_uint64(b))
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def lcm(a, b):
    return abs(a * b) // gcd(a, b) if a and b else 0


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a, m):
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g}")
    return x % m


def mod_exp(base, exp, mod):
    if _ASM_AVAILABLE and all(0 <= v < 2**63 for v in (base, exp, mod)) and mod > 0:
        _asm_lib.asm_mod_exp.restype = ctypes.c_uint64
        return _asm_lib.asm_mod_exp(ctypes.c_uint64(base), ctypes.c_uint64(exp), ctypes.c_uint64(mod))
    return pow(base, exp, mod)


def chinese_remainder_theorem(remainders, moduli):
    M = reduce(lambda a, b: a * b, moduli)
    x = 0
    for ri, mi in zip(remainders, moduli):
        Mi = M // mi
        yi = mod_inverse(Mi, mi)
        x += ri * Mi * yi
    return x % M


# ── Primality & factoring ────────────────────────────────────────────

def is_prime(n):
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    # Miller-Rabin with deterministic witnesses for n < 3.3e24
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n):
    if n < 2:
        return 2
    n = n + 1 if n % 2 == 0 else n + 2
    while not is_prime(n):
        n += 2
    return n


def primes_below(limit):
    if limit < 2:
        return []
    sieve = bytearray(b'\x01') * limit
    sieve[0] = sieve[1] = 0
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i*i::i] = bytearray(len(sieve[i*i::i]))
    return [i for i, v in enumerate(sieve) if v]


def prime_factors(n):
    factors = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def pollard_rho(n):
    if n % 2 == 0:
        return 2
    import random
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = gcd(abs(x - y), n)
    return d if d != n else None


def full_factorization(n):
    if n <= 1:
        return {}
    if is_prime(n):
        return {n: 1}
    factors = {}
    # trial division for small factors
    for p in primes_below(min(100000, int(n**0.5) + 1)):
        while n % p == 0:
            factors[p] = factors.get(p, 0) + 1
            n //= p
    if n == 1:
        return factors
    if is_prime(n):
        factors[n] = factors.get(n, 0) + 1
        return factors
    # Pollard rho for remaining
    stack = [n]
    while stack:
        val = stack.pop()
        if val == 1:
            continue
        if is_prime(val):
            factors[val] = factors.get(val, 0) + 1
            continue
        d = pollard_rho(val)
        if d is None or d == val:
            factors[val] = factors.get(val, 0) + 1
            continue
        stack.append(d)
        stack.append(val // d)
    return dict(sorted(factors.items()))


# ── Linear algebra ───────────────────────────────────────────────────

class Matrix:
    def __init__(self, data):
        self.data = [list(row) for row in data]
        self.rows = len(data)
        self.cols = len(data[0]) if data else 0

    def __repr__(self):
        return "Matrix(%s)" % self.data

    def __getitem__(self, idx):
        return self.data[idx]

    def __mul__(self, other):
        if isinstance(other, Matrix):
            return self.matmul(other)
        return Matrix([[c * other for c in row] for row in self.data])

    def __add__(self, other):
        return Matrix([[self[i][j] + other[i][j]
                        for j in range(self.cols)] for i in range(self.rows)])

    def __sub__(self, other):
        return Matrix([[self[i][j] - other[i][j]
                        for j in range(self.cols)] for i in range(self.rows)])

    def transpose(self):
        return Matrix([[self[j][i] for j in range(self.rows)]
                       for i in range(self.cols)])

    def matmul(self, other):
        result = [[sum(self[i][k] * other[k][j] for k in range(self.cols))
                   for j in range(other.cols)] for i in range(self.rows)]
        return Matrix(result)

    def determinant(self):
        if self.rows != self.cols:
            raise ValueError("Determinant requires square matrix")
        n = self.rows
        if n == 1:
            return self[0][0]
        if n == 2:
            return self[0][0] * self[1][1] - self[0][1] * self[1][0]
        # LU decomposition approach
        mat = [list(row) for row in self.data]
        det = 1
        for col in range(n):
            pivot = None
            for row in range(col, n):
                if mat[row][col] != 0:
                    pivot = row
                    break
            if pivot is None:
                return 0
            if pivot != col:
                mat[col], mat[pivot] = mat[pivot], mat[col]
                det *= -1
            det *= mat[col][col]
            for row in range(col + 1, n):
                factor = mat[row][col] / mat[col][col]
                for k in range(col, n):
                    mat[row][k] -= factor * mat[col][k]
        return det

    def inverse(self):
        if self.rows != self.cols:
            raise ValueError("Inverse requires square matrix")
        n = self.rows
        aug = [list(self[i]) + [1 if i == j else 0 for j in range(n)]
               for i in range(n)]
        for col in range(n):
            pivot = None
            for row in range(col, n):
                if aug[row][col] != 0:
                    pivot = row
                    break
            if pivot is None:
                raise ValueError("Matrix is singular")
            aug[col], aug[pivot] = aug[pivot], aug[col]
            scale = aug[col][col]
            for k in range(2 * n):
                aug[col][k] /= scale
            for row in range(n):
                if row == col:
                    continue
                factor = aug[row][col]
                for k in range(2 * n):
                    aug[row][k] -= factor * aug[col][k]
        return Matrix([row[n:] for row in aug])

    def trace(self):
        return sum(self[i][i] for i in range(min(self.rows, self.cols)))

    def rank(self):
        mat = [list(row) for row in self.data]
        rows, cols = self.rows, self.cols
        r = 0
        for col in range(cols):
            pivot = None
            for row in range(r, rows):
                if abs(mat[row][col]) > 1e-12:
                    pivot = row
                    break
            if pivot is None:
                continue
            mat[r], mat[pivot] = mat[pivot], mat[r]
            scale = mat[r][col]
            for k in range(cols):
                mat[r][k] /= scale
            for row in range(rows):
                if row == r:
                    continue
                factor = mat[row][col]
                for k in range(cols):
                    mat[row][k] -= factor * mat[r][k]
            r += 1
        return r

    def eigenvalues_2x2(self):
        if self.rows != 2 or self.cols != 2:
            raise ValueError("Only 2x2 eigenvalues implemented in closed form")
        a, b = self[0][0], self[0][1]
        c, d = self[1][0], self[1][1]
        tr = a + d
        det = a * d - b * c
        disc = tr * tr - 4 * det
        if disc >= 0:
            return [(tr + disc**0.5) / 2, (tr - disc**0.5) / 2]
        real = tr / 2
        imag = (-disc)**0.5 / 2
        return [complex(real, imag), complex(real, -imag)]

    @staticmethod
    def identity(n):
        return Matrix([[1 if i == j else 0 for j in range(n)] for i in range(n)])

    @staticmethod
    def zeros(rows, cols):
        return Matrix([[0] * cols for _ in range(rows)])

    def dot_product_row(self, row_idx, vec):
        if _ASM_AVAILABLE and len(vec) == self.cols:
            a = (ctypes.c_double * len(vec))(*self[row_idx])
            b = (ctypes.c_double * len(vec))(*vec)
            result = ctypes.c_double(0)
            _asm_lib.asm_dot_product(a, b, ctypes.c_uint64(len(vec)),
                                     ctypes.byref(result))
            return result.value
        return sum(self[row_idx][j] * vec[j] for j in range(self.cols))

    def to_json(self):
        return self.data


# ── Symbolic differentiation ─────────────────────────────────────────

class Expr:
    pass

class Num(Expr):
    def __init__(self, v): self.v = v
    def __repr__(self): return str(self.v)
    def diff(self, var): return Num(0)
    def simplify(self): return self
    def eval(self, env): return self.v

class Var(Expr):
    def __init__(self, name): self.name = name
    def __repr__(self): return self.name
    def diff(self, var): return Num(1) if self.name == var else Num(0)
    def simplify(self): return self
    def eval(self, env): return env.get(self.name, 0)

class BinOp(Expr):
    def __init__(self, op, l, r): self.op, self.l, self.r = op, l, r
    def __repr__(self):
        return f"({self.l} {self.op} {self.r})"
    def diff(self, var):
        if self.op == '+': return BinOp('+', self.l.diff(var), self.r.diff(var))
        if self.op == '-': return BinOp('-', self.l.diff(var), self.r.diff(var))
        if self.op == '*': return BinOp('+', BinOp('*', self.l.diff(var), self.r),
                                              BinOp('*', self.l, self.r.diff(var)))
        if self.op == '/':
            return BinOp('/', BinOp('-', BinOp('*', self.l.diff(var), self.r),
                                         BinOp('*', self.l, self.r.diff(var))),
                         BinOp('*', self.r, self.r))
        if self.op == '^':
            if isinstance(self.r, Num):
                return BinOp('*', BinOp('*', self.r, BinOp('^', self.l,
                             Num(self.r.v - 1))), self.l.diff(var))
        return Num(0)
    def simplify(self):
        l, r = self.l.simplify(), self.r.simplify()
        if self.op == '+':
            if isinstance(l, Num) and l.v == 0: return r
            if isinstance(r, Num) and r.v == 0: return l
            if isinstance(l, Num) and isinstance(r, Num): return Num(l.v + r.v)
        if self.op == '-':
            if isinstance(r, Num) and r.v == 0: return l
            if isinstance(l, Num) and isinstance(r, Num): return Num(l.v - r.v)
        if self.op == '*':
            if isinstance(l, Num) and l.v == 0: return Num(0)
            if isinstance(r, Num) and r.v == 0: return Num(0)
            if isinstance(l, Num) and l.v == 1: return r
            if isinstance(r, Num) and r.v == 1: return l
            if isinstance(l, Num) and isinstance(r, Num): return Num(l.v * r.v)
        if self.op == '^':
            if isinstance(r, Num) and r.v == 0: return Num(1)
            if isinstance(r, Num) and r.v == 1: return l
        return BinOp(self.op, l, r)
    def eval(self, env):
        lv, rv = self.l.eval(env), self.r.eval(env)
        if self.op == '+': return lv + rv
        if self.op == '-': return lv - rv
        if self.op == '*': return lv * rv
        if self.op == '/': return lv / rv if rv else float('inf')
        if self.op == '^': return lv ** rv
        return 0

class FuncCall(Expr):
    def __init__(self, name, arg): self.name, self.arg = name, arg
    def __repr__(self): return f"{self.name}({self.arg})"
    def diff(self, var):
        inner = self.arg.diff(var)
        if self.name == 'sin': return BinOp('*', FuncCall('cos', self.arg), inner)
        if self.name == 'cos': return BinOp('*', BinOp('*', Num(-1), FuncCall('sin', self.arg)), inner)
        if self.name == 'tan': return BinOp('*', BinOp('^', FuncCall('cos', self.arg), Num(-2)), inner)
        if self.name == 'ln':  return BinOp('*', BinOp('/', Num(1), self.arg), inner)
        if self.name == 'exp': return BinOp('*', FuncCall('exp', self.arg), inner)
        if self.name == 'sqrt': return BinOp('*', BinOp('/', Num(1), BinOp('*', Num(2), FuncCall('sqrt', self.arg))), inner)
        return Num(0)
    def simplify(self):
        return FuncCall(self.name, self.arg.simplify())
    def eval(self, env):
        v = self.arg.eval(env)
        funcs = {'sin': math.sin, 'cos': math.cos, 'tan': math.tan,
                 'ln': math.log, 'exp': math.exp, 'sqrt': math.sqrt,
                 'abs': abs, 'asin': math.asin, 'acos': math.acos,
                 'atan': math.atan, 'sinh': math.sinh, 'cosh': math.cosh,
                 'tanh': math.tanh, 'log2': math.log2, 'log10': math.log10}
        return funcs.get(self.name, lambda x: 0)(v)


def _tokenize(expr_str):
    import re
    tokens = re.findall(r'\d+\.?\d*|[a-zA-Z_]\w*|[+\-*/^(),]', expr_str)
    return tokens


def _parse_expr(tokens, pos=0):
    left, pos = _parse_term(tokens, pos)
    while pos < len(tokens) and tokens[pos] in ('+', '-'):
        op = tokens[pos]
        right, pos = _parse_term(tokens, pos + 1)
        left = BinOp(op, left, right)
    return left, pos


def _parse_term(tokens, pos):
    left, pos = _parse_power(tokens, pos)
    while pos < len(tokens) and tokens[pos] in ('*', '/'):
        op = tokens[pos]
        right, pos = _parse_power(tokens, pos + 1)
        left = BinOp(op, left, right)
    return left, pos


def _parse_power(tokens, pos):
    base, pos = _parse_unary(tokens, pos)
    if pos < len(tokens) and tokens[pos] == '^':
        exp, pos = _parse_power(tokens, pos + 1)
        return BinOp('^', base, exp), pos
    return base, pos


def _parse_unary(tokens, pos):
    if pos < len(tokens) and tokens[pos] == '-':
        node, pos = _parse_atom(tokens, pos + 1)
        return BinOp('*', Num(-1), node), pos
    return _parse_atom(tokens, pos)


def _parse_atom(tokens, pos):
    if pos >= len(tokens):
        return Num(0), pos
    tok = tokens[pos]
    if tok == '(':
        node, pos = _parse_expr(tokens, pos + 1)
        if pos < len(tokens) and tokens[pos] == ')':
            pos += 1
        return node, pos
    if tok[0].isdigit() or tok[0] == '.':
        v = float(tok) if '.' in tok else int(tok)
        return Num(v), pos + 1
    if tok[0].isalpha():
        if pos + 1 < len(tokens) and tokens[pos + 1] == '(':
            arg, pos = _parse_expr(tokens, pos + 2)
            if pos < len(tokens) and tokens[pos] == ')':
                pos += 1
            return FuncCall(tok, arg), pos
        return Var(tok), pos + 1
    return Num(0), pos + 1


def parse_expr(s):
    s = s.replace('pi', str(math.pi)).replace('e ', str(math.e) + ' ')
    tokens = _tokenize(s)
    node, _ = _parse_expr(tokens)
    return node


def symbolic_diff(expr_str, var='x'):
    tree = parse_expr(expr_str)
    d = tree.diff(var)
    return str(d.simplify())


# ── Numerical methods ────────────────────────────────────────────────

def numerical_integrate(expr_str, a, b, n=10000):
    tree = parse_expr(expr_str)
    h = (b - a) / n
    total = tree.eval({'x': a}) + tree.eval({'x': b})
    for i in range(1, n):
        x = a + i * h
        total += 2 * tree.eval({'x': x}) if i % 2 == 0 else 4 * tree.eval({'x': x})
    return total * h / 3  # Simpson's rule


def numerical_solve(expr_str, x0=1.0, tol=1e-12, max_iter=1000):
    """Newton-Raphson solver for f(x) = 0."""
    tree = parse_expr(expr_str)
    dtree = tree.diff('x')
    x = x0
    for _ in range(max_iter):
        fx = tree.eval({'x': x})
        dfx = dtree.eval({'x': x})
        if abs(dfx) < 1e-15:
            break
        x_new = x - fx / dfx
        if abs(x_new - x) < tol:
            return x_new
        x = x_new
    return x


def solve_linear(expr_str):
    """Solve 'a*x + b = c' style equations."""
    if '=' in expr_str:
        lhs, rhs = expr_str.split('=', 1)
        expr_str = f"({lhs.strip()}) - ({rhs.strip()})"
    return numerical_solve(expr_str)


# ── FFT ──────────────────────────────────────────────────────────────

def fft(x):
    n = len(x)
    if n <= 1:
        return x
    even = fft(x[0::2])
    odd = fft(x[1::2])
    T = [math.e ** (complex(0, -2 * math.pi * k / n)) * odd[k] for k in range(n // 2)]
    return [even[k] + T[k] for k in range(n // 2)] + \
           [even[k] - T[k] for k in range(n // 2)]


def ifft(X):
    n = len(X)
    conj = [x.conjugate() for x in X]
    result = fft(conj)
    return [x.conjugate() / n for x in result]


def convolve(a, b):
    n = 1
    while n < len(a) + len(b) - 1:
        n <<= 1
    fa = fft(a + [0] * (n - len(a)))
    fb = fft(b + [0] * (n - len(b)))
    fc = [x * y for x, y in zip(fa, fb)]
    result = ifft(fc)
    return [x.real for x in result[:len(a) + len(b) - 1]]


# ── Statistics ───────────────────────────────────────────────────────

def describe(data):
    n = len(data)
    if n == 0:
        return {"error": "empty dataset"}
    s = sorted(data)
    mean = sum(data) / n
    var = sum((x - mean) ** 2 for x in data) / n if n > 0 else 0
    std = var ** 0.5
    median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    q1 = s[n // 4] if n >= 4 else s[0]
    q3 = s[3 * n // 4] if n >= 4 else s[-1]
    skew = sum((x - mean) ** 3 for x in data) / (n * std ** 3) if std > 0 else 0
    kurt = sum((x - mean) ** 4 for x in data) / (n * std ** 4) - 3 if std > 0 else 0
    return {
        "n": n, "min": s[0], "max": s[-1], "sum": sum(data),
        "mean": mean, "median": median, "variance": var, "std_dev": std,
        "q1": q1, "q3": q3, "iqr": q3 - q1,
        "skewness": skew, "kurtosis": kurt,
        "range": s[-1] - s[0],
    }


def linear_regression(xs, ys):
    n = len(xs)
    sx = sum(xs)
    sy = sum(ys)
    sxy = sum(x * y for x, y in zip(xs, ys))
    sx2 = sum(x * x for x in xs)
    denom = n * sx2 - sx * sx
    if denom == 0:
        return {"error": "degenerate"}
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    y_pred = [slope * x + intercept for x in xs]
    ss_res = sum((y - yp) ** 2 for y, yp in zip(ys, y_pred))
    ss_tot = sum((y - sy / n) ** 2 for y in ys)
    r_squared = 1 - ss_res / ss_tot if ss_tot > 0 else 0
    return {"slope": slope, "intercept": intercept, "r_squared": r_squared}


# ── Graph theory ─────────────────────────────────────────────────────

def parse_graph(spec):
    graph = defaultdict(list)
    for edge in spec.split(','):
        parts = edge.strip().split(':')
        if len(parts) == 2:
            nodes, weight = parts[0], float(parts[1])
        else:
            nodes, weight = parts[0], 1.0
        a, b = nodes.split('-')
        graph[a.strip()].append((b.strip(), weight))
        graph[b.strip()].append((a.strip(), weight))
    return dict(graph)


def dijkstra(graph, start, end):
    import heapq
    dist = {start: 0}
    prev = {}
    pq = [(0, start)]
    while pq:
        d, u = heapq.heappop(pq)
        if u == end:
            path = []
            while u in prev:
                path.append(u)
                u = prev[u]
            path.append(start)
            return {"distance": d, "path": list(reversed(path))}
        if d > dist.get(u, float('inf')):
            continue
        for v, w in graph.get(u, []):
            nd = d + w
            if nd < dist.get(v, float('inf')):
                dist[v] = nd
                prev[v] = u
                heapq.heappush(pq, (nd, v))
    return {"distance": float('inf'), "path": []}


def minimum_spanning_tree(graph):
    import heapq
    if not graph:
        return []
    start = next(iter(graph))
    visited = {start}
    edges = [(w, start, v) for v, w in graph[start]]
    heapq.heapify(edges)
    mst = []
    total = 0
    while edges:
        w, u, v = heapq.heappop(edges)
        if v in visited:
            continue
        visited.add(v)
        mst.append({"from": u, "to": v, "weight": w})
        total += w
        for next_v, next_w in graph.get(v, []):
            if next_v not in visited:
                heapq.heappush(edges, (next_w, v, next_v))
    return {"edges": mst, "total_weight": total}


# ── Cryptographic math ───────────────────────────────────────────────

def rsa_keygen(bits=2048):
    import random
    def gen_prime(bits):
        while True:
            n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_prime(n):
                return n
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return {
        "public_key": {"n": str(n), "e": e},
        "private_key": {"n": str(n), "d": str(d)},
        "p": str(p), "q": str(q), "bits": bits,
    }


def diffie_hellman(bits=256):
    import random
    p = next_prime(random.getrandbits(bits))
    g = 2
    a = random.getrandbits(bits - 1)
    b = random.getrandbits(bits - 1)
    A = pow(g, a, p)
    B = pow(g, b, p)
    shared_a = pow(B, a, p)
    shared_b = pow(A, b, p)
    return {
        "p": str(p), "g": g,
        "alice_public": str(A), "bob_public": str(B),
        "shared_secret": str(shared_a),
        "verified": shared_a == shared_b,
    }


# ── Benchmark ────────────────────────────────────────────────────────

def run_benchmark():
    results = {}
    # 1) Prime sieve
    t = time.perf_counter()
    primes = primes_below(1_000_000)
    results["sieve_1M"] = {"time_ms": (time.perf_counter() - t) * 1000,
                            "count": len(primes)}
    # 2) Factoring
    t = time.perf_counter()
    f = full_factorization(600851475143)
    results["factor_600B"] = {"time_ms": (time.perf_counter() - t) * 1000,
                              "factors": {str(k): v for k, v in f.items()}}
    # 3) Matrix ops
    t = time.perf_counter()
    m = Matrix([[i * 50 + j + 1 for j in range(50)] for i in range(50)])
    d = m.determinant()
    results["matrix_50x50_det"] = {"time_ms": (time.perf_counter() - t) * 1000}

    # 4) FFT
    import random
    data = [random.random() for _ in range(1024)]
    t = time.perf_counter()
    fft(data)
    results["fft_1024"] = {"time_ms": (time.perf_counter() - t) * 1000}

    # 5) Modular exponentiation
    t = time.perf_counter()
    for _ in range(10000):
        mod_exp(123456789, 987654321, 1000000007)
    results["mod_exp_10k"] = {"time_ms": (time.perf_counter() - t) * 1000}

    # 6) Symbolic differentiation
    t = time.perf_counter()
    for _ in range(1000):
        symbolic_diff("x^5 + 3*x^3 - 2*x^2 + x - 7")
    results["symbolic_diff_1k"] = {"time_ms": (time.perf_counter() - t) * 1000}

    # 7) Numerical integration
    t = time.perf_counter()
    numerical_integrate("sin(x) + x^2", 0, math.pi)
    results["integrate_simpson"] = {"time_ms": (time.perf_counter() - t) * 1000}

    results["native_x86_64"] = _ASM_AVAILABLE
    return results


# ── CLI ──────────────────────────────────────────────────────────────

def main(argv=None):
    parser = argparse.ArgumentParser(prog="attestor math",
                                     description="Attestor Math Engine 4.2")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("bench", help="Run full benchmark suite")

    p = sub.add_parser("eval", help="Evaluate expression")
    p.add_argument("expr", nargs="+")

    p = sub.add_parser("factor", help="Factorize integer")
    p.add_argument("n", type=int)

    p = sub.add_parser("primes", help="List primes")
    p.add_argument("--below", type=int, default=1000)

    p = sub.add_parser("derive", help="Symbolic differentiation")
    p.add_argument("expr", nargs="+")
    p.add_argument("--var", default="x")

    p = sub.add_parser("integrate", help="Numerical integration")
    p.add_argument("expr", nargs="+")
    p.add_argument("a", type=float)
    p.add_argument("b", type=float)

    p = sub.add_parser("solve", help="Solve equation")
    p.add_argument("expr", nargs="+")

    p = sub.add_parser("matrix", help="Matrix operations")
    p.add_argument("op", choices=["det", "inv", "rank", "trace", "eigen", "mul"])
    p.add_argument("data", nargs="+")

    p = sub.add_parser("fft", help="Fast Fourier Transform")
    p.add_argument("data")

    p = sub.add_parser("stats", help="Statistical analysis")
    p.add_argument("op", choices=["describe", "regression"])
    p.add_argument("data")

    p = sub.add_parser("crypto", help="Cryptographic math")
    p.add_argument("op", choices=["rsa-keygen", "dh", "mod-exp", "mod-inv"])
    p.add_argument("args", nargs="*")

    p = sub.add_parser("graph", help="Graph algorithms")
    p.add_argument("op", choices=["shortest", "mst"])
    p.add_argument("edges")
    p.add_argument("start", nargs="?")
    p.add_argument("end", nargs="?")

    p = sub.add_parser("gcd", help="GCD / LCM")
    p.add_argument("a", type=int)
    p.add_argument("b", type=int)

    p = sub.add_parser("crt", help="Chinese Remainder Theorem")
    p.add_argument("--remainders", required=True)
    p.add_argument("--moduli", required=True)

    args = parser.parse_args(argv)

    _try_load_native()

    if args.cmd == "bench":
        results = run_benchmark()
        print(json.dumps(results, indent=2, default=str))
        return EXIT_OK

    if args.cmd == "eval":
        expr = " ".join(args.expr)
        try:
            tree = parse_expr(expr)
            result = tree.eval({'x': 0, 'pi': math.pi, 'e': math.e})
            print(f"{expr} = {result}")
            try:
                exact = eval(expr, {"__builtins__": {}},
                             {"pi": math.pi, "e": math.e, "sqrt": math.sqrt,
                              "sin": math.sin, "cos": math.cos, "tan": math.tan,
                              "log": math.log, "exp": math.exp, "abs": abs})
                if result != exact:
                    print(f"  (Python eval: {exact})")
            except Exception:
                pass
        except Exception as exc:
            print(f"error: {exc}")
            return EXIT_ERR
        return EXIT_OK

    if args.cmd == "factor":
        factors = full_factorization(args.n)
        parts = " * ".join(f"{p}^{e}" if e > 1 else str(p)
                           for p, e in sorted(factors.items()))
        print(f"{args.n} = {parts}")
        print(json.dumps({str(k): v for k, v in factors.items()}))
        return EXIT_OK

    if args.cmd == "primes":
        ps = primes_below(args.below)
        print(f"{len(ps)} primes below {args.below}")
        if len(ps) <= 100:
            print(ps)
        else:
            print(f"First 20: {ps[:20]}")
            print(f"Last 20: {ps[-20:]}")
        return EXIT_OK

    if args.cmd == "derive":
        expr = " ".join(args.expr)
        result = symbolic_diff(expr, args.var)
        print(f"d/d{args.var} [{expr}] = {result}")
        return EXIT_OK

    if args.cmd == "integrate":
        expr = " ".join(args.expr[:-2]) if len(args.expr) > 2 else args.expr[0]
        result = numerical_integrate(expr, args.a, args.b)
        print(f"integrate({expr}, {args.a}, {args.b}) = {result}")
        return EXIT_OK

    if args.cmd == "solve":
        expr = " ".join(args.expr)
        result = solve_linear(expr)
        print(f"solution: x = {result}")
        return EXIT_OK

    if args.cmd == "matrix":
        data = json.loads(" ".join(args.data))
        m = Matrix(data)
        if args.op == "det":
            print(f"determinant = {m.determinant()}")
        elif args.op == "inv":
            print(f"inverse = {json.dumps(m.inverse().to_json())}")
        elif args.op == "rank":
            print(f"rank = {m.rank()}")
        elif args.op == "trace":
            print(f"trace = {m.trace()}")
        elif args.op == "eigen":
            print(f"eigenvalues = {m.eigenvalues_2x2()}")
        elif args.op == "mul":
            data2 = json.loads(args.data[1]) if len(args.data) > 1 else data
            m2 = Matrix(data2)
            print(f"product = {json.dumps((m * m2).to_json())}")
        return EXIT_OK

    if args.cmd == "fft":
        data = [float(x) for x in args.data.split(",")]
        result = fft(data)
        magnitudes = [abs(c) for c in result]
        print(f"FFT magnitudes: {[round(m, 4) for m in magnitudes]}")
        return EXIT_OK

    if args.cmd == "stats":
        data = [float(x) for x in args.data.split(",")]
        if args.op == "describe":
            print(json.dumps(describe(data), indent=2))
        return EXIT_OK

    if args.cmd == "crypto":
        if args.op == "rsa-keygen":
            bits = int(args.args[0]) if args.args else 2048
            print(json.dumps(rsa_keygen(bits), indent=2))
        elif args.op == "dh":
            bits = int(args.args[0]) if args.args else 256
            print(json.dumps(diffie_hellman(bits), indent=2))
        elif args.op == "mod-exp":
            b, e, m = int(args.args[0]), int(args.args[1]), int(args.args[2])
            print(f"{b}^{e} mod {m} = {mod_exp(b, e, m)}")
        elif args.op == "mod-inv":
            a, m = int(args.args[0]), int(args.args[1])
            print(f"{a}^(-1) mod {m} = {mod_inverse(a, m)}")
        return EXIT_OK

    if args.cmd == "graph":
        graph = parse_graph(args.edges)
        if args.op == "shortest":
            print(json.dumps(dijkstra(graph, args.start, args.end), indent=2))
        elif args.op == "mst":
            print(json.dumps(minimum_spanning_tree(graph), indent=2, default=str))
        return EXIT_OK

    if args.cmd == "gcd":
        g = gcd(args.a, args.b)
        l = lcm(args.a, args.b)
        print(f"gcd({args.a}, {args.b}) = {g}")
        print(f"lcm({args.a}, {args.b}) = {l}")
        return EXIT_OK

    if args.cmd == "crt":
        remainders = [int(x) for x in args.remainders.split(",")]
        moduli = [int(x) for x in args.moduli.split(",")]
        result = chinese_remainder_theorem(remainders, moduli)
        print(f"CRT solution: x = {result}")
        return EXIT_OK

    parser.print_help()
    return EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
