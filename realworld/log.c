/*
 * Deliberately buggy "real-world" C. Sample input for the detector.
 */
#include <stdio.h>
#include <syslog.h>

/* format-string: the user string is used AS the format string. An attacker can
 * pass "%s%s%n" to read or corrupt memory. */
void log_message(const char *user_msg)
{
    printf(user_msg);
    syslog(LOG_INFO, user_msg);
}
