# AttestorLang 4.2

AttestorLang is Attestor's small, deterministic programming language. Its deliberately
strange surface borrows ideas from assembly, Haskell, Brainfuck, Malbolge,
Shakespeare Programming Language, C++, raw bytecode and A1Z26. Its execution
model is deliberately unstrange: every form compiles to a validated ATVM
program interpreted inside bounded memory.

It is **not** a native-code launcher and it gives programs no computer-control
authority. There are no filesystem, process, shell, socket, dynamic-library,
clock, random, FFI, JIT or executable-memory instructions. ATVM bytecode is
data; arbitrary x86, ARM and other native bytes are rejected.

## Quick start

From the Attestor release root:

```powershell
.\Run_AttestorLang.bat check integrations\attestorlang\examples\tour.owl
.\Run_AttestorLang.bat run integrations\attestorlang\examples\tour.owl
.\Run_AttestorLang.bat compile integrations\attestorlang\examples\tour.owl --out tour.owb
.\Run_AttestorLang.bat disasm tour.owb
.\Run_AttestorLang.bat run-bytecode tour.owb
```

Use `./Run_AttestorLang.sh` with the same arguments on Unix-like systems. Both
wrappers use Python isolated mode and forward arguments exactly. Direct
`python -I -B -X utf8 integrations/attestorlang/cli.py ...` invocation remains
supported.

The CLI is the host boundary: it reads only the explicit source/bytecode path
and optional explicit virtual input. The VM itself never receives a path.

## A small program

```text
attestor 4.2;
requires console.write;

scene Main {
    let shifted: i64 = asr(-64, 2);
    Attestor says text("ASR result: ");
    Attestor says number(shifted);

    asm {
        push 10;
        putc;
    }

    a1z26 {
        0-4-2 16-18-9-14-20
    }
}
```

`let` bindings are immutable. Braces and static `i64`/`text` types provide the
C++-style structure; pure expression evaluation supplies the Haskell-inspired
part. `Attestor says ...` is the Shakespeare-style output form.

## Capabilities

A source file can request—but cannot grant—these virtual capabilities:

- `console.write`: write into a bounded in-memory output buffer.
- `input.read`: read from immutable bytes supplied before execution. EOF is 0.

Effects must be declared. A program using output without
`requires console.write;` does not compile. Runtime grants are supplied out of
band; a missing grant produces a refusal before step zero.

Source parsing is also bounded: expression and unary nesting stop at 128
levels with a language error instead of leaking a Python recursion failure.

These are not host capabilities. No capability name for files, processes,
networking, credentials, native code or administrator access exists.

## The requested influences, precisely

- **ASM and ASR:** typed stack instructions, including exact signed 64-bit
  arithmetic shift right.
- **Haskell:** immutable `let` and pure expression builtins. This MVP does not
  claim Haskell compatibility or laziness.
- **Brainfuck:** embedded `brainfuck { ... }` with a bounded byte tape, wrapping
  cells, checked pointer movement, deterministic input and step accounting.
- **Malbolge:** pinned ten-trit `crazy(a, b)` and `rotrit(value)` operations. It
  does not implement Malbolge source encryption or self-modifying host code.
- **Shakespeare:** `scene Main` and `Actor says number/letter/text(...)`.
- **C++:** braces, scoped declarations, static fixed-width types and checked
  arithmetic—not C++ pointers, templates, undefined behavior or ABI access.
- **Raw machine code:** `.owb` is a canonical binary ATVM container with a
  payload SHA-256. It is verified and emulated, never executed by the CPU.
- **A1Z26:** a leading zero encodes a decimal literal; 1 through 26 encode
  letters. It is notation, not encryption.

See [SPEC_4.2.md](SPEC_4.2.md) for the normative MVP behavior.

## Exit status

- `0`: checked or completed successfully.
- `1`: a valid program hit a deterministic VM trap.
- `2`: source, bytecode, capability or boundary refusal.
- `130`: conventional caller interruption, when supplied by the shell.

## Tests

```powershell
python -B -m unittest discover -s integrations\attestorlang\tests -p "test_*.py" -v
```

Tests never invoke a native compiler or generated executable.
