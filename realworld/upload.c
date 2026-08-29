/*
 * A deliberately buggy "real-world" C file -- common production mistakes that
 * AttestorVonLuneberg flags. Not meant to be linked into anything.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_request(void)
{
    char name[16];
    /* scanf-unbounded: %s with no width happily overruns name[16]. */
    scanf("%s", name);

    char cmd[64];
    /* unsafe-libc: strcpy/strcat with no bounds. */
    strcpy(cmd, "ls ");
    strcat(cmd, name);

    /* command-exec: a shell command built from untrusted input. */
    system(cmd);
}

/* float-equality: comparing a double to an exact value with ==. */
int is_zero(double balance)
{
    return balance == 0.0;
}
