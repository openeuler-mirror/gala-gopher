/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Hubble_Zhu
 * Create: 2021-04-12
 * Description:
 ******************************************************************************/
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdarg.h>
#include "nprobe_fprintf.h"
#include "probe.h"

#define MACRO2STR1(MACRO) #MACRO
#define MACRO2STR2(MACRO) MACRO2STR1(MACRO)

__thread Probe *g_probe;

Probe *ProbeCreate(void)
{
    Probe *probe = NULL;
    probe = (Probe *)malloc(sizeof(Probe));
    if (probe == NULL)
        return NULL;

    memset(probe, 0, sizeof(Probe));

    probe->fifo = FifoCreate(MAX_FIFO_SIZE);
    if (probe->fifo == NULL) {
        free(probe);
        return NULL;
    }
    return probe;
}

void ProbeDestroy(Probe *probe)
{
    if (probe == NULL)
        return;

    if (probe->fifo != NULL)
        FifoDestroy(probe->fifo);

    free(probe);
    return;
}

ProbeMgr *ProbeMgrCreate(uint32_t size)
{
    ProbeMgr *mgr = NULL;
    mgr = (ProbeMgr *)malloc(sizeof(ProbeMgr));
    if (mgr == NULL)
        return NULL;

    memset(mgr, 0, sizeof(ProbeMgr));

    mgr->probes = (Probe **)malloc(sizeof(Probe *) * size);
    if (mgr->probes == NULL) {
        free(mgr);
        return NULL;
    }
    memset(mgr->probes, 0, sizeof(Probe *) * size);

    mgr->size = size;
    return mgr;
}

void ProbeMgrDestroy(ProbeMgr *mgr)
{
    if (mgr == NULL)
        return;

    if (mgr->probes != NULL) {
        for (int i = 0; i < mgr->probesNum; i++)
            ProbeDestroy(mgr->probes[i]);

        free(mgr->probes);
    }

    free(mgr);
    return;
}

int ProbeMgrPut(ProbeMgr *mgr, Probe *probe)
{
    if (mgr->probesNum == mgr->size)
        return -1;

    mgr->probes[mgr->probesNum] = probe;
    mgr->probesNum++;
    return 0;
}

Probe *ProbeMgrGet(ProbeMgr *mgr, const char *probeName)
{
    for (int i = 0; i < mgr->probesNum; i++) {
        if (strcmp(mgr->probes[i]->name, probeName) == 0)
            return mgr->probes[i];
    }
    return NULL;
}

int ProbeMgrLoadProbes(ProbeMgr *mgr)
{
    int count = 0;
    char *p = NULL;

    char probesList[] = MACRO2STR2(PROBES_LIST);
    char probesMetaList[] = MACRO2STR2(PROBES_META_LIST);

    Probe *probe;
    int ret;
    // get probe name
    count = 0;
    p = strtok(probesList, " ");
    while (p != NULL) {
        probe = ProbeCreate();
        if (probe == NULL)
            return -1;

        memcpy(probe->name, p, strlen(p));

        ret = ProbeMgrPut(mgr, probe);
        if (ret != 0)
            return 0;

        p = strtok(NULL, " ");
        count++;
    }

    // get probe meta path
    count = 0;
    p = strtok(probesMetaList, " ");
    while (p != NULL) {
        memcpy(mgr->probes[count]->metaPath, p, strlen(p));
        p = strtok(NULL, " ");
        count++;
    }

    // get probe process func
    char probeMainStr[MAX_PROBE_NAME_LEN];
    void *hdl = dlopen(NULL, RTLD_NOW | RTLD_GLOBAL);
    if (hdl == NULL)
        return -1;

    INFO("[PROBE] get probes_num: %u\n", mgr->probesNum);
    for (int i = 0; i < mgr->probesNum; i++) {
        (void)snprintf(probeMainStr, MAX_PROBE_NAME_LEN - 1, "probe_main_%s", mgr->probes[i]->name);
        mgr->probes[i]->func = dlsym(hdl, (char *)probeMainStr);
        if (mgr->probes[i]->func == NULL) {
            ERROR("[PROBE] Unknown func: %s\n", probeMainStr);
            dlclose(hdl);
            return -1;
        }
    }

    dlclose(hdl);
    return 0;
}

static inline int __isdigit(int ch)
{
    return (ch >= '0') && (ch <= '9');
}

static int __skip_atoi(const char **s)
{
    int i = 0;

    while (__isdigit(**s)) {
        i = i * 10 + *((*s)++) - '0';
    }
    return i;
}

static char* __number(char *str, unsigned long long num, int base, int size, int precision, int type)
{
    static const char digits[16] = "0123456789ABCDEF";  // we are called with base 8, 10 or 16, thus don't need "G..."
    char tmp[66];
    char c, sign, locase;
    int i;

    /* locase = 0 or 0x20. ORing digits or letters with 'locase'
     * produces same digits or (maybe lowercased) letters */
    locase = (type & SMALL);    // locase = 32(0x20)
    if (type & LEFT) {
        type &= ~ZEROPAD;
    }
    if (base < 2 || base > 16) {
        return NULL;
    }

    c = (type & ZEROPAD) ? '0' : ' ';

    sign = 0;
    if (type & SIGN) {
        if ((signed long long)num < 0) {
            sign = '-';
            num = -(signed long long)num;
            size--;
        } else if (type & PLUS) {
            sign = '+';
            size--;
        } else if (type & SPACE) {
            sign = ' ';
            size--;
        }
    }
    if (type & SPECIAL) {
        if (base == 16) {
            size -= 2;
        } else if (base == 8) {
            size--;
        }
    }
    i = 0;
    if (num == 0) {
        tmp[i++] = '0';
    } else {
        while (num != 0) {
            int res;
            res = ((unsigned long long)num) % ((unsigned)base);
            num = ((unsigned long long)num) / ((unsigned)base);
            tmp[i++] = (digits[res] | locase);
        }
    }
    if (i > precision) {
        precision = i;
    }
    size -= precision;
    /* 1. add num's symbol */
    if (!(type & (ZEROPAD + LEFT))) {
        while (size-- > 0) {
            *str++ = ' ';
        }
    }
    if (sign) {
        *str++ = sign;
    }
    /* 2. add '0' if base=8 or '0x' if base=16 */
    if (type & SPECIAL) {
        if (base == 8) {
            *str++ = '0';
        } else if (base == 16) {
            *str++ = '0';
            *str++ = ('X' | locase);
        }
    }
    /* 3. fill null and add num */
    if (!(type & LEFT)) {
        while (size-- > 0) {
            *str++ = c;
        }
    }
    while (i < precision--) {
        *str++ = '0';
    }
    while (i-- > 0) {
        *str++ = tmp[i];
    }
    while (size-- > 0) {
        *str++ = ' ';
    }
    return str;
}

int nprobe_fprintf(FILE *stream, const char *format, ...)
{
    int len;
    unsigned long long num;
    int i, base;
    char *str;
    const char *s;
    char *curFormat = (char *)format;

    int flags;          /* flags to number */
    int field_width;    /* width of output field */
    int precision;      /* min. # of digits for integers; max number of chars for from string */
    int qualifier;      /* 'h', 'l', or 'L' for integer fields */

    char *dataStr = (char *)malloc(MAX_DATA_STR_LEN);
    if (dataStr == NULL) {
        return -1;
    }
    memset(dataStr, 0, MAX_DATA_STR_LEN);

    va_list args;
    va_start(args, curFormat);

    for (str = dataStr; *curFormat; ++curFormat) {
        if (*curFormat != '%') {
            *str++ = *curFormat;
            continue;
        }
        /* process flags */
        flags = 0;
        repeat:
            ++curFormat;
        switch (*curFormat) {
            case '-':
                flags |= LEFT;
                goto repeat;
            case '+':
                flags |= PLUS;
                goto repeat;
            case ' ':
                flags |= SPACE;
                goto repeat;
            case '#':
                flags |= SPECIAL;
                goto repeat;
            case '0':
                flags |= ZEROPAD;
                goto repeat;
        }
        /* get field width */
        field_width = -1;
        if (__isdigit(*curFormat)) {
            field_width = __skip_atoi((const char **)&curFormat);
        } else if (*curFormat == '*') {
            ++curFormat;
            field_width = va_arg(args, int);
            if (field_width < 0) {
                field_width = -field_width;
                flags |= LEFT;
            }
        }
        /* get the precision */
        precision = -1;
        if (*curFormat == '.') {
            ++curFormat;
            if (__isdigit(*curFormat)) {
                precision = __skip_atoi((const char **)&curFormat);
            } else if (*curFormat == '*') {
                ++curFormat;
                precision = va_arg(args, int);
            }
            precision = (precision < 0) ? 0 : precision;
        }
        /* get the conversion qualifier */
        qualifier = -1;
        if (*curFormat == 'l' && *(curFormat + 1) == 'l') {
            qualifier = 'q';
            curFormat += 2;
        } else if (*curFormat == 'h' || *curFormat == 'l' || *curFormat == 'L') {
            qualifier = *curFormat;
            ++curFormat;
        }
        /* default base */
        base = 10;
        switch (*curFormat) {
            case 'c':
                if (!(flags & LEFT)) {
                    while (--field_width > 0) {
                        *str++ = ' ';
                    }
                }
                *str++ = (unsigned char)va_arg(args, int);
                while (--field_width > 0) {
                    *str++ = ' ';
                }
                continue;
            case 's':
                s = va_arg(args, char *);
                len = strnlen(s, precision);
                if (!(flags & LEFT)) {
                    while (len < field_width--) {
                        *str++ = ' ';
                    }
                }
                for (i = 0; i < len; ++i) {
                    *str++ = *s++;
                }
                while (len < field_width--) {
                    *str++ = ' ';
                }
                continue;
            case 'f':
            {
                char buf[64];
                char buf_format[16];
                buf[0] = 0;
                buf_format[0] = 0;
                if (precision > 0) {
                    if (field_width > 0) {
                        (void)snprintf((char *)buf_format, 16, "%%%d.%df", field_width, precision);
                    } else {
                        (void)snprintf((char *)buf_format, 16, "%%.%df", precision);
                    }
                } else {
                    (void)snprintf((char *)buf_format, 16, "%%f");
                }
                (void)snprintf((char *)buf, 64, buf_format, (double)va_arg(args, double));
                for (i = 0; buf[i] != '\0'; ++i) {
                    *str++ = buf[i];
                }
                continue;
            }
            case 'p':
                if (field_width == -1) {
                    field_width = 2 * sizeof(void *);
                    flags |= ZEROPAD;
                }
                str = __number(str,
                            (unsigned long)va_arg(args, void *), 16,
                            field_width, precision, flags);
                continue;
            case 'n':
                if (qualifier == 'l') {
                    long *ip = va_arg(args, long *);
                    *ip = (str - dataStr);
                } else {
                    int *ip = va_arg(args, int *);
                    *ip = (str - dataStr);
                }
                continue;
            case '%':
                *str++ = '%';
                continue;
            /* integer number formats - set up the flags and "break" */
            case 'o':
                base = 8;
                break;
            case 'x':
                flags |= SMALL;
            case 'X':
                base = 16;
                break;
            case 'd':
            case 'i':
                flags |= SIGN;
            case 'u':
                break;
            default:
                *str++ = '%';
                if (*curFormat) {
                    *str++ = *curFormat;
                } else {
                    --curFormat;
                }
                continue;
        }
        if (qualifier == 'l') {
            num = va_arg(args, unsigned long);
            if (flags & SIGN) {
                num = (signed long)num;
            }
        } else if (qualifier == 'q') {
            num = va_arg(args, unsigned long long);
            if (flags & SIGN) {
                num = (signed long long)num;
            }
        } else if (qualifier == 'h') {
            num = (unsigned short)va_arg(args, int);
            if (flags & SIGN) {
                num = (signed short)num;
            }
        } else {
            num = va_arg(args, unsigned int);
            if (flags & SIGN) {
                num = (signed int)num;
            }
        }
        str = __number(str, num, base, field_width, precision, flags);
    }
    *str = '\0';
    va_end(args);

    int ret = FifoPut(g_probe->fifo, (void *)dataStr);
    if (ret != 0) {
        ERROR("[PROBE %s] fifo full.\n", g_probe->name);
        (void)free(dataStr);
        return -1;
    }

    uint64_t msg = 1;
    ret = write(g_probe->fifo->triggerFd, &msg, sizeof(uint64_t));
    if (ret != sizeof(uint64_t)) {
        ERROR("[PROBE %s] send trigger msg to eventfd failed.\n", g_probe->name);
        return -1;
    }

    return 0;

}