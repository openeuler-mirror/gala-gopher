/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: eank
 * Create: 2023/7/7
 * Description:
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include "http_parse_wrapper.h"
#include "../model/multiple_map.h"

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define YES     1,
#define NO      0,
#define YES16   YES YES YES YES YES YES YES YES YES YES YES YES YES YES YES YES
#define NO16    NO NO NO NO NO NO NO NO NO NO NO NO NO NO NO NO
#define NO128   NO16 NO16 NO16 NO16 NO16 NO16 NO16 NO16

#define CHECK_EOF() \
    do { \
        if (buf == buf_end) { \
            *ret = -2; \
            return NULL; \
        } \
    } while(0)

#define IS_PRINTABLE_ASCII(c) ((unsigned char)(c) - 040u < 0137u)

#define IS_EXCEPT_CHAR(c) \
    CHECK_EOF(); \
    if (*buf != c) { \
        *ret = -1; \
        return NULL; \
    } else { \
        buf++; \
    } \

#define DO_MARCH(ch, end) \
    do { \
        if (unlikely(!IS_PRINTABLE_ASCII(ch))) { \
            /* allow HT, allow SP, excluding DEL */ \
            if ((likely((unsigned char)ch < '\040') && likely(ch != '\011')) || unlikely(ch == '\177')) { \
                goto end; \
            } \
        } \
        buf++; \
    } while(0)

// Visible ASCII table
static char g_visible_chars[256] = {
 // NUL SOH STX ETX EOT ENQ ACK BEL BS  HT  LF  VT  FF  CR  SO  SI
 // DLE DC1 DC2 DC3 DC4 NAK SYN ETB CAN EM  SUB ESC FS  GS  RS  US
    NO16 NO16
 //  SP  !  "   #   $   %   &   '  (   )  *   +   ,   -   .   /
    NO YES NO YES YES YES YES YES NO NO YES YES NO  YES YES  NO
 //  0   1   2   3   4   5   6   7   8   9   :   ;  <  =  >  ?
    YES YES YES YES YES YES YES YES YES YES NO  NO NO NO NO NO
 //  @  A   B   C   D   E   F   G   H   I   J   K   L   M   N   O
    NO YES YES YES YES YES YES YES YES YES YES YES YES YES YES YES
 //  P   Q   R   S   T   U   V   W   X   Y   Z   [  \  ]  ^   _
    YES YES YES YES YES YES YES YES YES YES YES NO NO NO YES YES
 //  `   a   b   c   d   e   f   g   h   i   j   k   l   m   n   o
    YES16
 //  p   q   r   s   t   u   v   w   x   y   z   {  |   }  ~   DEL
    YES YES YES YES YES YES YES YES YES YES YES NO YES NO YES NO
 // Non-ASCII characters
    NO128
};

static char *parse_token(char *buf, char *buf_end, char end_ch, char **ret_str, size_t *ret_len, int *ret)
{
    char *buf_start = buf;

    while(1) {
        if (*buf == end_ch) {
            break;
        } else if (!g_visible_chars[(unsigned char)*buf]) {
            *ret = -1;
            DEBUG("[HTTP1.x PARSER]parse token failed, find invisitable character[%c]\n", *buf);
            return NULL;
        }
        buf++;
        CHECK_EOF();
    }
    *ret_str = buf_start;
    *ret_len = buf - buf_start;

    return buf;
}

static char *parse_http_path(char *buf, char *buf_end, char **path, size_t *plen, int *ret)
{
    char *buf_start = buf;
    char end_char = ' ';

    while(1) {
        if (*buf == end_char) {
            break;
        }
        if (unlikely(!IS_PRINTABLE_ASCII(*buf))) {
            if ((unsigned char)*buf < '\040' || *buf == '\177') {
                *ret = -1;
                DEBUG("[HTTP1.x PARSER]parse http path failed, find invisitable character[%c]\n", *buf);
                return NULL;
            }
        }
        buf++;
        CHECK_EOF();
    }

    *path = buf_start;
    *plen = buf - buf_start;

    return buf;
}

static char *parse_http_version(char *buf, char *buf_end, int *version, int *ret)
{
    /* ex: HTTP/1.1 */
    IS_EXCEPT_CHAR('H');
    IS_EXCEPT_CHAR('T');
    IS_EXCEPT_CHAR('T');
    IS_EXCEPT_CHAR('P');
    IS_EXCEPT_CHAR('/');
    IS_EXCEPT_CHAR('1');
    IS_EXCEPT_CHAR('.');
    if (*buf < '0' || *buf > '9') {
        DEBUG("[HTTP1.x PARSER]parse http version failed, character[%c] is not a number \n", *buf);
        buf++;
        *ret = -1;
        return NULL;
    }
    *version = *buf - '0';
    buf++;
    return buf;
}

static char *parse_res_status(char *buf, char *buf_end, int *status, int *ret)
{
    int value = 0;

    for (int i = 0; i < 3; i++) {
        if (*buf < '0' || *buf > '9') {
            DEBUG("[HTTP1.x PARSER]parse http response status failed, character[%c] is not a number \n", *buf);
            buf++;
            *ret = -1;
            return NULL;
        }
        value = value * 10 + (*buf - '0');
        buf++;
    }
    *status = value;
    return buf;
}

static char *parse_header_value(char *buf, char *buf_end, char **value, size_t *value_len, int *ret)
{
    char *buf_start = buf;

    /* check if there is non-printable char within the next 8 bytes, this is the hottest code; manually inlined */
    while(likely(buf_end - buf >= 8)) {
        DO_MARCH(*buf, FOUND);
        DO_MARCH(*buf, FOUND);
        DO_MARCH(*buf, FOUND);
        DO_MARCH(*buf, FOUND);
        DO_MARCH(*buf, FOUND);
        DO_MARCH(*buf, FOUND);
        DO_MARCH(*buf, FOUND);
        DO_MARCH(*buf, FOUND);
        continue;
    }
    /* check last 7 bytes */
    for (;; ++buf) {
        CHECK_EOF();
        DO_MARCH(*buf, FOUND);
    }
FOUND:
    if (likely(*buf == '\015')) {
        buf++;
        IS_EXCEPT_CHAR('\012');
        *value_len = buf - 2 - buf_start;
    } else if (*buf == '\012') {
        buf++;
        *value_len = buf - 1 - buf_start;
    } else {
        *ret = -1;
        DEBUG("[HTTP1.x PARSER]parse header value failed, find invisitable character[%c]\n", *buf);
        return NULL;
    }
    *value = buf_start;

    return buf;
}

static char *parse_headers(char *buf, char *buf_end, size_t *header_num, http_header headers[], int *ret)
{
    int num;
    for (num = 0; num < MAX_HEADERS_SIZE; num++) {
        CHECK_EOF();
        if (*buf == '\015') {
            buf++;
            IS_EXCEPT_CHAR('\012');
            break;
        } else if (*buf == '\012') {
            buf++;
            break;
        }
        if ((num == 0) || (*buf != ' ' && *buf != '\t')) {
            /* parse name such as: Host/Content-Type/User-Agent ... */
            buf = parse_token(buf, buf_end, ':', &headers[num].name, &headers[num].name_len, ret);
            if (buf == NULL) {
                return NULL;
            }
            if (headers[num].name_len == 0) {
                DEBUG("[HTTP1.x PARSER] parse header failed, empty name\n");
                *ret = -1;
                return NULL;
            }
            buf++;
            do {    // skip SPs and TABs after ':'
                CHECK_EOF();
                buf++;
            } while(*buf == ' ' || *buf == '\t');
        } else {
            headers[num].name = NULL;
            headers[num].name_len = 0;
        }
        char *value;
        size_t value_len;
        buf = parse_header_value(buf, buf_end, &value, &value_len, ret);
        if (buf == NULL) {
            return NULL;
        }
        /* delete SPs and TABs at value ending */
        size_t j = value_len;
        for (; j > 0; j--) {
            char c = *(value + j - 1);
            if (c != ' ' && c != '\t') {
                break;
            }
        }
        headers[num].value = value;
        headers[num].value_len = j;
    }
    *header_num = num;
    return buf;
}

static char *parse_request(char *buf, int buf_len, http_request* req, int *ret)
{
    if (buf == NULL || buf_len == 0) {
        return NULL;
    }
    char *buf_end = buf + buf_len;

    /* if first line is empty, skip*/
    if (*buf == '\015') {
        buf++;
        IS_EXCEPT_CHAR('\012');
    } else if (*buf == '\012') {
        buf++;
    }

    /* parse request line */
    buf = parse_token(buf, buf_end, ' ', &req->method, &req->method_len, ret);
    if (buf == NULL) {
        return NULL;
    }
    if (req->method_len == 0) {
        *ret = -1;
        DEBUG("[HTTP1.x PARSER]request parse method failed, empty method.\n");
        return NULL;
    }
    do {    // skip SPs after method
        buf++;
        CHECK_EOF();
    } while (*buf == ' ');
    buf = parse_http_path(buf, buf_end, &req->path, &req->path_len, ret);
    if (buf == NULL) {
        return NULL;
    }
    if (req->path_len == 0) {
        *ret = -1;
        DEBUG("[HTTP1.x PARSER]request parse path failed, empty path.\n");
        return NULL;
    }
    do {    // skip SPs after path
        buf++;
        CHECK_EOF();
    } while (*buf == ' ');
    buf = parse_http_version(buf, buf_end, &req->minor_version, ret);
    if (buf == NULL) {
        return NULL;
    }
    /* req first line parsing completed */
    if (*buf == '\015') {
        buf++;
        IS_EXCEPT_CHAR('\012');
    } else if (*buf == '\012') {
        buf++;
    } else {    // there sholdn't be valid characters at the end of line
        *ret = -1;
        DEBUG("[HTTP1.x PARSER]found garbage at the end of request first line.\n");
        return NULL;
    }
    /* parse request headers */
    return parse_headers(buf, buf_end, &req->num_headers, req->headers, ret);
}

static char *parse_response(char *buf, int buf_len, http_response* res, int *ret)
{
    char *buf_end = buf + buf_len;

    /* parse first line */
    /* parse version "HTTP/1.x" */
    buf = parse_http_version(buf, buf_end, &res->minor_version, ret);
    if (buf == NULL) {
        return NULL;
    }
    if (*buf != ' ') {
        *ret = -1;
        DEBUG("[HTTP1.x PARSER]response parse version failed, there shold be SP after HTTP/1.x \n");
        return NULL;
    }
    do {    // skip SPs after version
        buf++;
        CHECK_EOF();
    } while(*buf == ' ');

    /* parse status value: [:digit:][:digit:][:digit:] <msg> */
    buf = parse_res_status(buf, buf_end, &res->status, ret);
    if (buf == NULL) {
        return NULL;
    }
    /* parse status msg */
    buf = parse_header_value(buf, buf_end, &res->msg, &res->msg_len, ret);
    if (buf == NULL) {
        return NULL;
    }
    /* msg_len == 0 is OK */
    if (res->msg_len > 0) {
        if (*res->msg == ' ') {
            /* delete preceding SPs, because func parse_header_value allow SP */
            do {
                res->msg++;
                res->msg_len--;
            } while(*res->msg == ' ');
        } else {
            /* garbage found, bacause there should be SP between status and msg */
            *ret = -1;
            DEBUG("[HTTP1.x PARSER] response parsie failed, found garbage between status code and msg\n");
            return NULL;
        }
    }

    /* parse request headers */
    return parse_headers(buf, buf_end, &res->num_headers, res->headers, ret);
}

int http_parse_request_headers(struct raw_data_s* raw_data, http_request* req)
{
    int ret = 0;
    char *buf = &raw_data->data[raw_data->current_pos];
    char *buf_start = buf;
    size_t buf_size = raw_data->data_len;

    buf = parse_request(buf, buf_size, req, &ret);
    if (buf == NULL) {
        DEBUG("[HTTP1.x PARSER WRAPPER] Parse request failed, data_len: %d, current_pos: %d, data:\n%s\n",
                                                        raw_data->data_len, raw_data->current_pos, raw_data->data);
        return ret;
    }
    return buf - buf_start;
}

int http_parse_response_headers(struct raw_data_s* raw_data, http_response* resp)
{
    int ret = 0;
    char *buf = &raw_data->data[raw_data->current_pos];
    char *buf_start = buf;
    size_t buf_size = raw_data->data_len;

    buf = parse_response(buf, buf_size, resp, &ret);
    if (buf == NULL) {
        DEBUG("[HTTP1.x PARSER WRAPPER] Parse response failed, data_len: %d, current_pos: %d, data:\n%s\n",
                                                        raw_data->data_len, raw_data->current_pos, raw_data->data);
        return ret;
    }
    return buf - buf_start;
}


int get_http_header_value_by_key(struct http_header headers[], size_t num_headers, char *key, char *value, int vlen_max)
{
    if (key == NULL || value == NULL) {
        return -1;
    }
    size_t klen = strlen(key);
    for (size_t i = 0; i < num_headers; i++) {
        if ((headers[i].name_len == klen) && (strncmp(headers[i].name, key, klen) == 0)) {
            int vlen = (headers[i].value_len < vlen_max) ? headers[i].value_len : (vlen_max - 1);
            (void)snprintf(value, vlen + 1, "%s", headers[i].value);
            return 0;
        }
    }
    return -1;
}
