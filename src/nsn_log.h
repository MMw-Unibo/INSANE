#ifndef NSN_LOG_H
#define NSN_LOG_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

//--------------------------------------------------------------------------------------------------
// Colors
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

struct logger_config
{
    char *filename;
    int   ts;    // enable timestamp
    int   level; // enable level
    int   color; // enable color
    char *title;
};

struct logger
{
    char *filename;
    FILE *file;
};

enum logger_level
{
    LOGGER_LEVEL_ERROR,
    LOGGER_LEVEL_WARN,
    LOGGER_LEVEL_INFO,
    LOGGER_LEVEL_DEBUG,
    LOGGER_LEVEL_TRACE
};

#ifdef NSN_ENABLE_LOGGER
# define log(level, ...) logger_log(level, ##__VA_ARGS__)
# define log_trace(...)  logger_log(LOGGER_LEVEL_TRACE, ##__VA_ARGS__)
# define log_debug(...)  logger_log(LOGGER_LEVEL_DEBUG, ##__VA_ARGS__)
# define log_info(...)   logger_log(LOGGER_LEVEL_INFO, ##__VA_ARGS__)
# define log_warn(...)   logger_log(LOGGER_LEVEL_WARN, ##__VA_ARGS__)
# define log_error(...)  logger_log(LOGGER_LEVEL_ERROR, ##__VA_ARGS__)
#else
# define log(level, ...)
# define log_trace(...)
# define log_debug(...)
# define log_info(...)
# define log_warn(...)
# define log_error(...)
#endif // NSN_ENABLE_LOGGER

int  logger_init(struct logger_config *config);
void logger_log(int level, char *fmt, ...);
void logger_close();
void logger_set_level(int level);
void logger_set_title(char *title);
void logger_enable_timestamp(int enable);

#endif // NSN_LOG_H

#ifdef NSN_LOG_IMPLEMENTATION_H

struct logger        s_logger;
struct logger_config s_config = {
    .filename = NULL,
    .ts       = 1,
    .level    = LOGGER_LEVEL_INFO,
    .color    = 1,
    .title    = NULL,
};

int
logger_init(struct logger_config *config)
{
    memset(&s_logger, 0, sizeof(s_logger));

    if (config)
    {
        s_config.filename = config->filename;
        s_config.ts       = config->ts;
        s_config.level    = config->level;
        s_config.color    = config->color;
        s_config.title    = config->title;
    }

    if (s_config.filename)
    {
        s_logger.filename = s_config.filename;
        s_logger.file     = fopen(s_logger.filename, "a");
        if (!s_logger.file)
        {
            fprintf(stderr, "Failed to open log file: %s\n", s_logger.filename);
            return -1;
        }
    }

    return 0;
}

void
logger_set_level(int level)
{
    s_config.level = level;
}

void
logger_set_title(char *title)
{
    s_config.title = title;
}

void
logger_enable_timestamp(int enable)
{
    s_config.ts = enable;
}

void
logger_close()
{
    if (s_logger.file)
    {
        fclose(s_logger.file);
    }
}

void
logger_log(int level, char *fmt, ...)
{
    if (level > s_config.level)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);

    char   buf[4096];
    size_t buflen = 0;

    if (s_config.title)
    {
        buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "[%s ", s_config.title);
    }
    else
    {
        buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "[");
    }

    if (s_config.ts)
    {
        time_t     t  = time(NULL);
        struct tm *tm = localtime(&t);
        buflen += strftime(buf + buflen, sizeof(buf) - buflen, "%Y-%m-%d %H:%M:%S ", tm);
    }

    if (s_config.color)
    {
        switch (level)
        {
        case LOGGER_LEVEL_ERROR:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen,
                               ANSI_COLOR_RED "ERROR" ANSI_COLOR_RESET);
            break;
        case LOGGER_LEVEL_WARN:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen,
                               ANSI_COLOR_YELLOW "WARN" ANSI_COLOR_RESET);
            break;
        case LOGGER_LEVEL_INFO:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen,
                               ANSI_COLOR_GREEN "INFO" ANSI_COLOR_RESET);
            break;
        case LOGGER_LEVEL_DEBUG:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen,
                               ANSI_COLOR_BLUE "DEBUG" ANSI_COLOR_RESET);
            break;
        case LOGGER_LEVEL_TRACE:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen,
                               ANSI_COLOR_CYAN "TRACE" ANSI_COLOR_RESET);
            break;
        }
    }
    else
    {
        switch (level)
        {
        case LOGGER_LEVEL_ERROR:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "ERROR");
            break;
        case LOGGER_LEVEL_WARN:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "WARN");
            break;
        case LOGGER_LEVEL_INFO:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "INFO");
            break;
        case LOGGER_LEVEL_DEBUG:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "DEBUG");
            break;
        case LOGGER_LEVEL_TRACE:
            buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "TRACE");
            break;
        }
    }

    buflen += snprintf(buf + buflen, sizeof(buf) - buflen, "] ");

    buflen += vsnprintf(buf + buflen, sizeof(buf) - buflen, fmt, args);

    FILE *file = s_config.filename ? s_logger.file : stderr;
    fprintf(file, "%s", buf);

    va_end(args);
}

#endif // NSN_LOG_IMPLEMENTATION_H