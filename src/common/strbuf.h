#ifndef __STRBUF_H__
#define __STRBUF_H__

#include <string.h>

typedef struct {
    char *buf;
    int len;
    int size;
} strbuf_t;

void strbuf_update_offset(strbuf_t *dest, int offset)
{
    dest->buf += offset;
    dest->size -= offset;
}

void strbuf_append_chr(strbuf_t *dest, char c)
{
    *dest->buf = c;
    strbuf_update_offset(dest, 1);
}

void strbuf_append_str(strbuf_t *dest, const char *str, const int strLen)
{
    memcpy(dest->buf, str, strLen);
    strbuf_update_offset(dest, strLen);
}

int strbuf_append_chr_with_check(strbuf_t *dest, char c)
{
    if (dest->size <= 0) {
        return -1;
    }
    strbuf_append_chr(dest, c);
    return 0;
}

int strbuf_append_str_with_check(strbuf_t *dest, const char *str, const int strLen)
{
    if (dest->size < strLen) {
        return -1;
    }
    strbuf_append_str(dest, str, strLen);
    return 0;
}

#endif