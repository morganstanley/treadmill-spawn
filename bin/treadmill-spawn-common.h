#ifndef BIN_TREADMILL_SPAWN_H_
#define BIN_TREADMILL_SPAWN_H_

#define _GNU_SOURCE

#include <errno.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_APP_NAME              256
#define MAX_SOCKET                108
#define MAX_ID                    (MAX_SOCKET - 7)
#define MAX_INSTANCE_NAME         (MAX_APP_NAME + 11)
#define PREFIX_LENGTH             5
#define INITIALIZE_PREFIX         "init:"
#define PRINT_PREFIX              "prnt:"
#define DONE_PREFIX               "done:"
#define UDS_LINE_LENGTH           (PREFIX_LENGTH + NAME_MAX + 1)
#define MAX_LINE                  (MAX_SOCKET + MAX_APP_NAME + NAME_MAX + 4)
#define RETURN_CODE_STOP          2
#define INSTANCE_FILE             "data/instance"
#define INSTANCE_URL              "http://localhost/instance/"
#define TIMEOUT_FILE              "data/timeout"
#define API_RETRY                 5

#define ERR_EXIT(id, ...) _err_exit(id, __FILE__, __LINE__, errno, __VA_ARGS__)

static inline
void log_debug(const char *id, const char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    fprintf(stderr, "DEBUG [%s] ", id);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static inline
void log_error(const char *id, const char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    fprintf(stderr, "ERROR [%s] ", id);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static inline
void _err_exit(const char *id, const char *file, const int line,
               const int err, const char *msg, ...)
{
    const char *errmsg = strerror(err);
    va_list ap;

    va_start(ap, msg);
    fprintf(stderr, "ERROR [%s] %s:%d %s(%d) ", id, file, line, errmsg, err);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    raise(SIGABRT);
}


#endif  // BIN_TREADMILL_SPAWN_H_
