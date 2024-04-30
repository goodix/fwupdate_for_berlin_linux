#ifndef __LOG_WRAPPER_H_
#define __LOG_WRAPPER_H_

typedef enum {
    NLOG_LEVEL_ERROR = 1,
    NLOG_LEVEL_WARNING,
    NLOG_LEVEL_INFO,
    NLOG_LEVEL_DEBUG,
    NLOG_LEVEL_GDTDEBUG,
} NLOG_LEVEL_ENUM;

void NLOG(NLOG_LEVEL_ENUM level, const char *fmt, ...);

#define NLOGE(f, ...)   NLOG(NLOG_LEVEL_ERROR, (f), ## __VA_ARGS__)
#define NLOGW(f, ...)   NLOG(NLOG_LEVEL_WARNING, (f), ## __VA_ARGS__)
#define NLOGI(f, ...)   NLOG(NLOG_LEVEL_INFO, (f), ## __VA_ARGS__)
#define NLOGD(f, ...)   NLOG(NLOG_LEVEL_DEBUG, (f), ## __VA_ARGS__)
#define NLOGN(f, ...)   NLOG(NLOG_LEVEL_GDTDEBUG, (f), ## __VA_ARGS__)

void NLOG_ARRAY_U8(const uint8_t *array, int len,
        int num_per_line, NLOG_LEVEL_ENUM log_level);
#endif