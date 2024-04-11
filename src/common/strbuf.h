#ifndef __STRBUF_H__
#define __STRBUF_H__

#include <string.h>

typedef struct {
    char *buf;
    size_t len;
    int size;
} strbuf_t;

void strbuf_update_offset(strbuf_t *dest, int offset);
void strbuf_append_chr(strbuf_t *dest, char c);
void strbuf_append_str(strbuf_t *dest, const char *str, const int strLen);
int strbuf_append_chr_with_check(strbuf_t *dest, char c);
int strbuf_append_str_with_check(strbuf_t *dest, const char *str, const int strLen);

#endif