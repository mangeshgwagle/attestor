# AttestorLang and ATVM MVP specification 4.2

This document is normative for the Attestor 4.2 implementation in this directory.

## Source

Source is strict UTF-8, at most 256 KiB, contains no NUL, and uses ASCII
identifiers. The header is exactly `attestor 4.2;`. The MVP has exactly one entry
scene named `Main`. Parenthesized-expression and unary nesting are each capped
at 128 levels and fail with a source error before Python's recursion boundary.

```ebnf
program   = "attestor", "4", ".", "2", ";", requirement*, scene ;
requirement = "requires", ("console.write" | "input.read"), ";" ;
scene     = "scene", "Main", "{", statement*, "}" ;
statement = let | say | asm | brainfuck | a1z26 ;
let       = "let", identifier, [":", ("i64" | "text")], "=", expression, ";" ;
say       = identifier, "says", ("number" | "letter" | "text"),
            "(", expression, ")", ";" ;
asm       = "asm", "{", assembly*, "}", [";"] ;
brainfuck = "brainfuck", "{", brainfuck-characters, "}", [";"] ;
a1z26     = "a1z26", "{", numeric-tokens, "}", [";"] ;
```

Expressions have ordinary `* / %` then `+ -` precedence, parentheses, signed
unary minus, immutable binding references, UTF-8 text literals and pure
`asr`, `crazy`, and `rotrit` builtins. There is no assignment form; a `let`
slot is initialized exactly once.

## Integer semantics

- `i64` is signed two's-complement 64-bit.
- Structured `+`, `-`, `*`, unary minus and assembly `ADD`, `SUB`, `MUL`, `NEG`
  trap on overflow.
- `ADDW`, `SUBW`, `MULW` wrap modulo 2^64.
- `DIV` is mathematical floor division. `MOD` has the divisor's sign.
- Division by zero and `I64_MIN / -1` overflow trap.
- `ASR` is signed arithmetic shift right. `SHL`, `LSR` and `ASR` accept counts
  0 through 63 only. `SHL` is checked; `LSR` shifts the 64-bit bit pattern.
- Comparisons push `0` or `1` as `i64`.

## Malbolge-inspired operations

Operands are ten-trit words, integers 0 through 59048 inclusive.

`CRAZY(a,b)` applies this table independently from least-significant to
most-significant trit, with `table[a_trit][b_trit]` orientation:

```text
      b=0 b=1 b=2
a=0   1   0   0
a=1   1   0   2
a=2   2   2   1
```

`ROTRIT` rotates the least-significant trit into the most-significant position
of a ten-trit word. Both operations are pure and never mutate VM instructions.

## Brainfuck

The commands `><+-.,[]` are supported. Other characters inside the embedded
block are comments, except `}` which closes the AttestorLang block.

- Tape cells are bytes and wrap modulo 256.
- Pointer movement beyond either selected tape boundary traps.
- `.` requires `console.write` and writes one byte.
- `,` requires `input.read`; end of virtual input stores zero.
- Loops compile to verified absolute ATVM instruction indexes.
- Every command and jump consumes a VM step.

## A1Z26

A token whose first component is zero is a decimal literal. Each following
component must be one decimal digit: `0-4-2` pushes 42. Other components must
be 1 through 26 and decode to an assembly mnemonic:
`16-18-9-14-20` is `PRINT`. Negative values are a positive literal followed
by encoded `NEG`. A1Z26 provides no secrecy.

## ATVM container

An `.owb` file is:

```text
"ATVM42\\0" | payload_length:u32be | SHA256(payload):32 bytes | payload
```

The payload is canonical strict JSON containing only:

```text
capabilities, code, constants, format, local_types
```

Instructions are arrays of integer opcode plus fixed operands. Before any
execution, the verifier rejects unknown opcodes, wrong operand counts, invalid
indexes, unsupported capability names, missing effect declarations, multiple
or misplaced HALTs, unreachable instructions, stack underflow, type errors,
immutable-local rewrites, invalid jumps and inconsistent control-flow joins.

The container digest detects damage; it is not a signature or authorization.

## Runtime boundary

Defaults and compiled maxima:

| Resource | Default | Hard maximum |
|---|---:|---:|
| VM steps | 1,000,000 | 10,000,000 |
| Stack values | 4,096 | 4,096 |
| Tape cells | 4,096 | 65,536 |
| Output | 64 KiB | 1 MiB |
| Input | 1 MiB | 1 MiB |
| Instructions | 100,000 | 100,000 |
| Bytecode container | 2 MiB | 2 MiB |

The VM exposes no filesystem, process, shell, network, native compiler,
dynamic-library, executable-memory, environment, time or random instruction.
Resource-profile selection may lower limits; it cannot add authority.

## Evidence

Every run records source and bytecode hashes, a deterministic instruction
trace hash, required/granted/used/denied capabilities, limits, usage, base64
output and its hash, and explicit false host-execution fields. The canonical
report excludes timestamps, elapsed time, PIDs, absolute paths and randomness,
so the same program, input, grants and limits yield the same report bytes.
