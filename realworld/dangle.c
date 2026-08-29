/*
 * Deliberately buggy "real-world" C: functions that hand back pointers into
 * their own stack frame. Sample input for the detector.
 */
#include <stdio.h>

/* c-return-local-address: returns a local array -> dangling pointer. */
char *make_greeting(const char *name)
{
    char buf[64];
    snprintf(buf, sizeof buf, "hello, %s", name);
    return buf;
}

/* c-return-local-address: returns the address of a local scalar. */
int *counter_ptr(void)
{
    int n = 0;
    return &n;
}

/* c-strncpy-truncation: strncpy may leave dst without a terminating NUL. */
void copy_name(char *dst, const char *src)
{
    strncpy(dst, src, 32);
}
