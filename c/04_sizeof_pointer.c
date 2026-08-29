/*
 * THE BUG:           `sizeof` applied to an array that has "decayed" into a
 *                    pointer function parameter -- you measure the pointer, not
 *                    the array.
 * WHY IT'S MISSED:   In the caller, `sizeof buf` genuinely is the buffer size, so
 *                    the idiom is muscle memory. The moment you pass the array to
 *                    a helper, the parameter is a *pointer*, and `sizeof(param)`
 *                    becomes 8 (the pointer width) no matter how big the buffer
 *                    is. The copy silently truncates to 8 bytes and everything
 *                    downstream reads uninitialized memory. There is no crash, no
 *                    warning at default settings, just quietly wrong data.
 * HOW TO DETECT:     gcc/clang `-Wsizeof-pointer-memaccess` (in `-Wall`) catches
 *                    exactly this. ASan (`-fsanitize=address`) shows the
 *                    uninitialized tail if you read past the copied bytes.
 * THE FIX:           Never `sizeof` a pointer parameter. Pass the length
 *                    explicitly, or keep the operation in a scope where the array
 *                    type is still visible.
 *
 * Build & run:  cc -std=c11 -Wall 04_sizeof_pointer.c && ./a.out
 */
#include <stdio.h>
#include <string.h>

/* `src` looks like an array but is really `const char *`.
 * sizeof(src) is the size of a pointer (8), not the buffer. */
static void copy_message(char *dst, const char src[])
{
    memcpy(dst, src, sizeof(src));   /* copies 8 bytes, not strlen(src)+1 */
}

int main(void)
{
    const char message[] = "ship it on Friday";   /* 18 bytes incl. '\0' */
    char buffer[64];
    memset(buffer, '?', sizeof buffer);
    buffer[sizeof buffer - 1] = '\0';

    copy_message(buffer, message);

    printf("source : \"%s\" (%zu bytes)\n", message, sizeof message);
    printf("copy   : \"%s\"\n", buffer);
    printf("\n>>> BUG: only the first %zu bytes ('%.*s') were copied; the rest\n",
           sizeof(char *), (int)sizeof(char *), buffer);
    printf("    is whatever was already in `buffer` ('?' padding here).\n");

    /* THE FIX -- pass the length, or copy strlen+1:
     *   static void copy_message(char *dst, const char *src) {
     *       memcpy(dst, src, strlen(src) + 1);
     *   }
     */
    return 0;
}
