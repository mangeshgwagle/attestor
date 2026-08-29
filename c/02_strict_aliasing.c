/*
 * THE BUG:           Type punning two pointers of different types that alias the
 *                    same memory ("strict aliasing" violation).
 * WHY IT'S MISSED:   The function is three lines long and obviously correct when
 *                    you read it: we store 1 into *i, then store into *f, then
 *                    return *i, which is still 1. Compile at -O0 and it prints 1.
 *                    Ship it. Then someone turns on -O2 and the optimizer -- which
 *                    is *allowed* to assume a `float*` and an `int*` never point
 *                    at the same object -- reorders the loads and the program
 *                    silently returns a different value. The source never changed.
 * HOW TO DETECT:     gcc/clang `-Wstrict-aliasing=2 -O2` warns on many cases;
 *                    `-fsanitize=undefined` may flag it; the robust fix is to
 *                    stop relying on warnings and use memcpy / a union instead.
 * THE FIX:           Copy bytes with memcpy (the compiler optimizes it away), or
 *                    compile the whole program with `-fno-strict-aliasing`.
 *
 * Build & run BOTH ways to see them disagree:
 *   cc -O0 -std=c11 02_strict_aliasing.c -o a0 && ./a0
 *   cc -O2 -std=c11 02_strict_aliasing.c -o a2 && ./a2
 */
#include <stdio.h>
#include <string.h>

/* Writes through an int*, then through a float*, then re-reads the int.
 * If the two pointers happen to alias, the result depends on the optimizer. */
__attribute__((noinline))
static int aliased_read(int *i, float *f)
{
    *i = 1;
    *f = 0.0f;        /* the compiler assumes this cannot touch *i */
    return *i;        /* -O0 reloads (0); -O2 may reuse the cached 1 */
}

int main(void)
{
    int storage = 0;
    /* Hand the same address to both parameters -- they alias. */
    int result = aliased_read(&storage, (float *)&storage);

    printf("aliased_read returned %d\n", result);
    printf("(Compile at -O0 vs -O2 and watch this number change.)\n");

    /* THE FIX -- well-defined, and just as fast under optimization:
     *   static int safe_read(int *i, float *f) {
     *       *i = 1;
     *       float zero = 0.0f;
     *       memcpy(f, &zero, sizeof zero);
     *       int out; memcpy(&out, i, sizeof out);
     *       return out;
     *   }
     */
    (void)memcpy; /* silence -Wunused-includes pedants */
    return 0;
}
