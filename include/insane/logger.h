#ifndef INSANE_LOGGER_H
#define INSANE_LOGGER_H

#include <stdarg.h>
#include <stdio.h>

#define ASCII_CYAN    "\x1b[36m"
#define ASCII_MAGENTA "\x1b[35m"
#define ASCII_YELLOW  "\x1b[33m"
#define ASCII_BLUE    "\x1b[34m"
#define ASCII_RED     "\x1b[31m"
#define ASCII_GREEN   "\x1b[32m"
#define ASCII_NONE    "\x1b[0m"

//--------------------------------------------------------------------------------------------------
void log_error(const char *fmt, ...);

void log_warn(const char *fmt, ...);

void log_info(const char *fmt, ...);

void log_debug(char *fmt, ...);

void log_trace(char *fmt, ...);

void vlog_trace(char *fmt, va_list ap);

//--------------------------------------------------------------------------------------------------
#define LOG_ERROR(FMT, ...)
#define LOG_WARN(FMT, ...)
#define LOG_INFO(FMT, ...)
#define LOG_DEBUG(FMT, ...)
#define LOG_TRACE(FMT, ...)
#define VLOG_TRACE(FMT, ap)

#if LOG_LEVEL >= 100
#undef LOG_ERROR
#define LOG_ERROR(...) log_error(__VA_ARGS__)
#endif

#if LOG_LEVEL >= 200
#undef LOG_WARN
#define LOG_WARN(fmt, ...) log_warn(fmt, ##__VA_ARGS__)
#endif

#if LOG_LEVEL >= 300
#undef LOG_INFO
#define LOG_INFO(fmt, ...) log_info(fmt, ##__VA_ARGS__)
#endif

#if LOG_LEVEL >= 400
#undef LOG_DEBUG
#define LOG_DEBUG(fmt, ...) log_debug(fmt, ##__VA_ARGS__)
#endif

#if LOG_LEVEL >= 500
#undef LOG_TRACE
#define LOG_TRACE(fmt, ...) log_trace(fmt, ##__VA_ARGS__)
#undef VLOG_TRACE
#define VLOG_TRACE(fmt, ap) vlog_trace(fmt, ap)
#endif

#endif // INSANE_LOGGER_H