#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "log_wrapper.h"

#define SCREENLEN           (300)
#define MAXLOGLEN           (500)
#define MAX_TIME_STR_LEN    128
#define MAX_STR_LEN         256


static uint8_t gu8LogLevel = NLOG_LEVEL_ERROR;

void NLOG(NLOG_LEVEL_ENUM level, const char *fmt, ...)
{
    char gcMsg[SCREENLEN];

    va_list arg;

    if (gu8LogLevel >= (level)) {
        va_start(arg, fmt);
        vsnprintf(gcMsg, SCREENLEN, fmt, arg);
        va_end(arg);
        printf("[%c] %s\n", "0EWID"[level], gcMsg);
    }
}

void NLOG_ARRAY_U8(const uint8_t *array, int len,
        int num_per_line, NLOG_LEVEL_ENUM log_level)
{
    int str_len = 0;
    int i;
    char str_buf[MAX_STR_LEN] = {0};

    for (i = 0; i < len; i++) {
        str_len += snprintf(str_buf + str_len, MAX_STR_LEN - str_len, "%02x ", array[i]);
        if (i != 0 && (i % num_per_line == (num_per_line - 1))) {
            if (NLOG_LEVEL_ERROR == log_level) {
                NLOGE("%s", str_buf);
            } else if (NLOG_LEVEL_INFO == log_level) {
                NLOGI("%s", str_buf);
            }
            memset(str_buf, 0, sizeof(str_buf));
            str_len = 0;
        }
    }
    if (str_len) {
        if (NLOG_LEVEL_ERROR == log_level) {
            NLOGE("%s\n", str_buf);
        } else if (NLOG_LEVEL_INFO == log_level) {
            NLOGI("%s\n", str_buf);
        }
    }
}