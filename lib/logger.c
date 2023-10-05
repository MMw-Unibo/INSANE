#include <insane/logger.h>

//--------------------------------------------------------------------------------------------------
static void do_log(const char *fmt, const char *level, const char *color, va_list *ap) {
    char buff[512];
    snprintf(buff, sizeof(buff), "%s[%s]%s %s\n", color, level, ASCII_NONE, fmt);

    vfprintf(stderr, buff, *ap);
}

//--------------------------------------------------------------------------------------------------
static void do_vlog(const char *fmt, const char *level, const char *color, va_list *ap) {
    char buff[512];
    snprintf(buff, sizeof(buff), "%s[%s]%s %s\n", color, level, ASCII_NONE, fmt);

    vfprintf(stderr, buff, *ap);
}

//--------------------------------------------------------------------------------------------------
void log_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    do_log(fmt, "error", ASCII_RED, &ap);

    va_end(ap);
}

//--------------------------------------------------------------------------------------------------
void log_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    do_log(fmt, "warn", ASCII_YELLOW, &ap);

    va_end(ap);
}

//--------------------------------------------------------------------------------------------------
void log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    do_log(fmt, "info", ASCII_GREEN, &ap);

    va_end(ap);
}

//--------------------------------------------------------------------------------------------------
void log_debug(char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    do_log(fmt, "debug", ASCII_BLUE, &ap);

    va_end(ap);
}

//--------------------------------------------------------------------------------------------------
void log_trace(char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    do_log(fmt, "trace", ASCII_CYAN, &ap);

    va_end(ap);
}

//--------------------------------------------------------------------------------------------------
void vlog_trace(char *fmt, va_list ap) {
    do_vlog(fmt, "trace", ASCII_CYAN, (void *)&ap);
}
