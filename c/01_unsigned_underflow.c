/*
 * THE BUG:           Subtracting unsigned integers (size_t) that "go negative".
 * WHY IT'S MISSED:   The code reads like ordinary signed arithmetic. The minus
 *                    sign, the `< 0` test, the variable names -- everything
 *                    looks correct. But `size_t` is *unsigned*, so the result of
 *                    `a - b` when b > a is not a small negative number: it wraps
 *                    around to a gigantic positive value near 2^64. The `< 0`
 *                    branch is therefore *dead code that can never run*, and the
 *                    "remaining capacity" is reported as ~18 quintillion bytes.
 * HOW TO DETECT:     gcc/clang `-Wsign-conversion -Wsign-compare` warns; UBSan's
 *                    `-fsanitize=unsigned-integer-overflow` flags the wrap at
 *                    run time; clang-tidy `bugprone-*` catches the comparison.
 * THE FIX:           Compare before subtracting: `if (used > capacity) ...`,
 *                    and never let an unsigned subtraction underflow.
 *
 * Build & run:  cc -std=c11 -Wall -Wextra 01_unsigned_underflow.c && ./a.out
 */
#include <stdio.h>
#include <stddef.h>

/* Returns how many more bytes fit in a buffer of `capacity` that already
 * holds `used` bytes. Looks bulletproof. It is not. */
static size_t remaining(size_t capacity, size_t used)
{
    size_t left = capacity - used;     /* underflows when used > capacity   */
    if (left < 0)                      /* DEAD CODE: size_t is never < 0     */
        return 0;
    return left;
}

int main(void)
{
    size_t capacity = 100;
    size_t used     = 120;             /* over budget by 20 bytes            */

    size_t left = remaining(capacity, used);

    printf("capacity = %zu, used = %zu\n", capacity, used);
    printf("remaining() reports %zu bytes free\n", left);
    printf("...so we 'safely' write %zu more bytes into a full buffer.\n", left);

    if (left > capacity)
        printf("\n>>> BUG: %zu > capacity. The (capacity - used) underflowed.\n", left);

    /* THE FIX:
     *   static size_t remaining(size_t capacity, size_t used) {
     *       return used >= capacity ? 0 : capacity - used;
     *   }
     */
    return 0;
}
