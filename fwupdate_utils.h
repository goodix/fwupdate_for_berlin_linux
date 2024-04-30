#ifndef _FWUPDATE_UTILS_H_
#define _FWUPDATE_UTILS_H_

#include <stdint.h>

static inline uint32_t le32_to_cpu(uint32_t value)
{
    uint32_t test = 1;
    uint8_t *p = (uint8_t *)&test;

    if (*p == 1)
        /* cpu little edition no need for change */
        return value;

    /* cpu big edition */
    return ((value << 24) & 0xFF000000) | ((value << 8) & 0x00FF0000) |
            ((value >> 8) & 0x0000FF00) | ((value >> 24) & 0x000000FF);
}

static inline uint32_t cpu_to_le32(uint32_t value)
{
    uint32_t test = 1;
    uint8_t *p = (uint8_t *)&test;

    if (*p == 1)
        /* cpu little edition no need for change */
        return value;

    /* cpu big edition */
    return ((value << 24) & 0xFF000000) | ((value << 8) & 0x00FF0000) |
            ((value >> 8) & 0x0000FF00) | ((value >> 24) & 0x000000FF);
}

static inline uint32_t le32_to_cpup(uint8_t *value)
{
    uint32_t test = 1;
    uint8_t *p = (uint8_t *)&test;

    if (*p == 1)
        /* cpu little edition no need for change */
        return *((uint32_t *)value);
    else {
        /* cpu big edition */
        return ((value[0] << 24) & 0xFF000000) | ((value[1] << 16) & 0x00FF0000) |
                ((value[2] << 8) & 0x0000FF00) | (value[3] & 0x000000FF);
    }
}

static inline uint16_t le16_to_cpu(uint16_t value)
{
        uint32_t test = 1;
        uint8_t *p = (uint8_t *)&test;
        if (*p == 1)
                /* cpu little edition no need for change */
                return value;
        else
                /* cpu big edition */
                return ((value << 8) & 0xFF00) | ((value >> 8) & 0x00FF);
}

static inline uint16_t cpu_to_le16(uint16_t value)
{
        uint32_t test = 1;
        uint8_t *p = (uint8_t *)&test;
        if (*p == 1)
                /* cpu little edition no need for change */
                return value;

        /* cpu big edition */
        return ((value << 8) & 0xFF00) | ((value >> 8) & 0x00FF);
}

static inline uint16_t le16_to_cpup(uint8_t *value)
{
        uint32_t test = 1;
        uint8_t *p = (uint8_t *)&test;
        if (*p == 1)
                /* cpu little edition no need for change */
                return *((uint16_t *)value);
        else
                /* cpu big edition */
                return ((value[0] << 8) & 0xFF00) | (value[1] & 0x00FF);
}

#endif