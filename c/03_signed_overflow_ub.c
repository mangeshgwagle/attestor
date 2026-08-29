/*
 * THE BUG:           An overflow check that relies on signed overflow --
 *                    `x + 1 < x` -- which is undefined behavior, so the compiler
 *                    deletes the check.
 * WHY IT'S MISSED:   This is the textbook "I'll detect overflow by seeing if the
 *                    number got smaller" trick, and it *looks* like sound logic.
 *                    But signed overflow is UB in C, so the compiler is entitled
 *                    to assume `x + 1` is always greater than `x` and fold the
 *                    whole comparison to a constant `false`. The result is a
 *                    program that computes `x + 1`, observes it is -2147483648
 *                    (plainly less than x), and *still* insists `x + 1 < x` is
 *                    false. The contradiction is invisible in the source.
 * HOW TO DETECT:     `-fsanitize=undefined` (UBSan) pinpoints the exact line:
 *                    "signed integer overflow: 2147483647 + 1 cannot be
 *                    represented in type 'int'". `-Wstrict-overflow=2` can warn.
 * THE FIX:           Check *before* overflowing: `if (x > INT_MAX - 1)`.
 *                    (`-fwrapv` also makes wraparound defined, but that hides the
 *                    real bug instead of fixing it.)
 *
 * Build & run:  cc -std=c11 03_signed_overflow_ub.c && ./a.out
 *   Then compare:  cc -fwrapv ...   and   cc -fsanitize=undefined ...
 */
#include <stdio.h>
#include <limits.h>

/* "Returns 1 if adding 1 to x would overflow." It does not. */
__attribute__((noinline))
static int adding_one_overflows(int x)
{
    return x + 1 < x;     /* UB at x == INT_MAX -> folded to constant 0 */
}

int main(void)
{
    int x = INT_MAX;
    int next = x + 1;     /* materialized: wraps to INT_MIN in practice */

    printf("x        = %d\n", x);
    printf("x + 1    = %d   (clearly smaller than x)\n", next);
    printf("x + 1 < x ? the compiler says: %s\n",
           adding_one_overflows(x) ? "true" : "false");

    printf("\n>>> BUG: x+1 is %d, x is %d, yet 'x+1 < x' was computed as %s.\n",
           next, x, adding_one_overflows(x) ? "true" : "false");
    printf("    The overflow 'check' was optimized into a no-op.\n");

    /* THE FIX:
     *   static int adding_one_overflows(int x) { return x > INT_MAX - 1; }
     */
    return 0;
}
