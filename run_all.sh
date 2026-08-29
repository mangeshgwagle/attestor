#!/usr/bin/env bash
# Build and run every "almost no-one can find" bug demo.
#
# C and C++ demos are compiled and executed for real, with -Wall -Wextra so you
# can see which traps the compiler catches and which it waves through. The
# strict-aliasing demo is built at BOTH -O0 and -O2 to show the optimizer change
# the program's output. Haskell demos run if GHC is installed; otherwise the
# documented expected output is printed from each file's header.
#
# Usage:  ./run_all.sh
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-$(command -v gcc || command -v cc || command -v clang)}"
CXX="${CXX:-$(command -v g++ || command -v c++ || command -v clang++)}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

rule()  { printf '\n========================================================\n'; }
title() { rule; printf '### %s\n' "$1"; rule; }

# ----------------------------------------------------------------- C
title "C  -  low-level UB & optimizer traps"
for src in "$here"/c/*.c; do
    name="$(basename "$src")"
    printf '\n--- %s ---\n' "$name"
    if [ "$name" = "02_strict_aliasing.c" ]; then
        for O in 0 2; do
            "$CC" -O$O -std=c11 "$src" -o "$work/a" 2>/dev/null \
                && { printf '[built -O%s]\n' "$O"; "$work/a"; }
        done
    else
        if "$CC" -std=c11 -Wall -Wextra "$src" -o "$work/a" 2>"$work/warn"; then
            "$work/a"
            [ -s "$work/warn" ] && { printf '[compiler warnings]\n'; cat "$work/warn"; }
        else
            printf '[build failed]\n'; cat "$work/warn"
        fi
    fi
done

# ----------------------------------------------------------------- C++
title "C++  -  abstraction & type-system traps"
for src in "$here"/cpp/*.cpp; do
    name="$(basename "$src")"
    printf '\n--- %s ---\n' "$name"
    if "$CXX" -std=c++20 -Wall -Wextra "$src" -o "$work/cx" 2>"$work/warn"; then
        "$work/cx"
        [ -s "$work/warn" ] && { printf '[compiler warnings]\n'; cat "$work/warn"; }
    else
        printf '[build failed]\n'; cat "$work/warn"
    fi
done

# ----------------------------------------------------------------- Haskell
title "Haskell  -  laziness & numeric traps"
RUNGHC="$(command -v runghc || command -v runhaskell || true)"
for src in "$here"/haskell/*.hs; do
    name="$(basename "$src")"
    printf '\n--- %s ---\n' "$name"
    if [ -n "$RUNGHC" ]; then
        ( cd "$work" && "$RUNGHC" "$src" )    # may intentionally throw / overflow
    else
        printf '[GHC not installed -- documented expected output:]\n'
        # Echo the EXPECTED block from the file header.
        awk '/EXPECTED (OUTPUT|BEHAVIOR)/{f=1} f && /^-- /{print "  " substr($0,4)} f && !/^-- /{exit}' "$src"
    fi
done

# ----------------------------------------------------------------- AttestorVonLuneberg
title "AttestorVonLuneberg  -  finding the bugs (planted + real-world) from source"
if command -v python3 >/dev/null 2>&1; then
    # A fixed --seed keeps this run reproducible; drop it and his personality is random.
    python3 "$here/detector/attestor.py" --no-color --seed 0 \
        "$here/c" "$here/cpp" "$here/haskell" "$here/realworld"
    printf '\n[self-test: every planted + real-world bug should be detected]\n'
    python3 "$here/detector/attestor.py" --self-test --seed 0
    printf '\n[codegen: he can also WRITE code]\n'
    ( cd "$here/detector" && python3 codegen.py --stdout-only )
else
    printf '[python3 not found -- skipping AttestorVonLuneberg]\n'
fi

rule
printf 'Done. The demos print a ">>> BUG" line; Attestor finds the same bugs (and more) from source.\n'
