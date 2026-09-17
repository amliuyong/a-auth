/* Isolated Linux integration-test clock. Only CLOCK_REALTIME advances;
 * Tokio timers and process deadlines retain the real monotonic clock.
 * This library is never linked into the service or any release artifact. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int clock_gettime(clockid_t clock_id, struct timespec *result) {
    int status = (int)syscall(SYS_clock_gettime, clock_id, result);
    if (status != 0 || clock_id != CLOCK_REALTIME) {
        return status;
    }
    const char *path = getenv("A_AUTH_TEST_CLOCK_FILE");
    if (path == NULL) {
        return status;
    }
    FILE *file = fopen(path, "r");
    if (file != NULL) {
        long offset = 0;
        if (fscanf(file, "%ld", &offset) == 1) {
            result->tv_sec += offset;
        }
        fclose(file);
    }
    return status;
}
