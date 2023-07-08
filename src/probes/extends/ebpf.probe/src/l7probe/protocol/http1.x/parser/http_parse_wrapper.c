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

#include "http_parse_wrapper.h"

#ifdef _MSC_VER
#define ALIGNED(n) _declspec(align(n))
#else
#define ALIGNED(n) __attribute__((aligned(n)))
#endif

#define IS_PRINTABLE_ASCII(c) ((unsigned char)(c)-040u < 0137u)

// Check the buf is at the end, if end then return -2
#define CHECK_EOF()                                                                                                                \
    if (buf == buf_end) {                                                                                                          \
        *ret = -2;                                                                                                                 \
        return NULL;                                                                                                               \
    }

#define EXPECT_CHAR_NO_CHECK(ch)                                                                                                   \
    if (*buf++ != ch) {                                                                                                            \
        *ret = -1;                                                                                                                 \
        return NULL;                                                                                                               \
    }

// Check if the char is expected
#define EXPECT_CHAR(ch)                                                                                                            \
    CHECK_EOF();                                                                                                                   \
    EXPECT_CHAR_NO_CHECK(ch);

#define ADVANCE_TOKEN(tok, len)                                                                                                 \
    do {                                                                                                                           \
        const char *tok_start = buf;                                                                                               \
        static const char ALIGNED(16) ranges2[16] = "\000\040\177\177";                                                            \
        int found2;                                                                                                                \
        buf = find_char_fast(buf, buf_end, ranges2, 4, &found2);                                                                    \
        if (!found2) {                                                                                                             \
            CHECK_EOF();                                                                                                           \
        }                                                                                                                          \
        while (1) {                                                                                                                \
            if (*buf == ' ') {                                                                                                     \
                break;                                                                                                             \
            } else if (!IS_PRINTABLE_ASCII(*buf)) {                                                                      \
                if ((unsigned char)*buf < '\040' || *buf == '\177') {                                                              \
                    *ret = -1;                                                                                                     \
                    return NULL;                                                                                                   \
                }                                                                                                                  \
            }                                                                                                                      \
            ++buf;                                                                                                                 \
            CHECK_EOF();                                                                                                           \
        }                                                                                                                          \
        tok = tok_start;                                                                                                           \
        len = buf - tok_start;                                                                                                  \
    } while (0);

#define PARSE_INT(valp_, mul_)                                                                                                     \
    if (*buf < '0' || '9' < *buf) {                                                                                                \
        buf++;                                                                                                                     \
        *ret = -1;                                                                                                                 \
        return NULL;                                                                                                               \
    }                                                                                                                              \
    *(valp_) = (mul_) * (*buf++ - '0');

#define PARSE_INT_3(valp_)                                                                                                         \
    do {                                                                                                                           \
        int res_ = 0;                                                                                                              \
        PARSE_INT(&res_, 100)                                                                                                      \
        *valp_ = res_;                                                                                                             \
        PARSE_INT(&res_, 10)                                                                                                       \
        *valp_ += res_;                                                                                                            \
        PARSE_INT(&res_, 1)                                                                                                        \
        *valp_ += res_;                                                                                                            \
    } while (0)

/**
 * Judge if the buf is complete
 *
 * @param buf
 * @param buf_end
 * @param last_len
 * @param ret
 * @return
 */
static const char *is_complete(const char *buf, const char *buf_end, size_t last_len, size_t *ret)
{
    int ret_cnt = 0;
    buf = last_len < 3 ? buf : buf + last_len - 3;

    while (1) {
        CHECK_EOF()
        if (*buf == '\015') {
            ++buf;
            CHECK_EOF()
            EXPECT_CHAR('\012')
            ++ret_cnt;
        } else if (*buf == '\012') {
            ++buf;
            ++ret_cnt;
        } else {
            ++buf;
            ret_cnt = 0;
        }
        if (ret_cnt == 2) {
            return buf;
        }
    }

//    *ret = -2;
//    return NULL;
}

static const char *token_char_map = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\1\0\1\1\1\1\1\0\0\1\1\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0"
                                    "\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\1\1"
                                    "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\0\1\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static const char *find_char_fast(const char *buf, const char *buf_end, const char *ranges, size_t ranges_size, int *found)
{
    *found = 0;
#if __SSE4_2__
    if (buf_end - buf >= 16) {
        __m128i ranges16 = _mm_loadu_si128((const __m128i *)ranges);

        size_t left = (buf_end - buf) & ~15;
        do {
            __m128i b16 = _mm_loadu_si128((const __m128i *)buf);
            int r = _mm_cmpestri(ranges16, ranges_size, b16, 16, _SIDD_LEAST_SIGNIFICANT | _SIDD_CMP_RANGES | _SIDD_UBYTE_OPS);
            if (r != 16) {
                buf += r;
                *found = 1;
                break;
            }
            buf += 16;
            left -= 16;
        } while (left != 0);
    }
#else
    /* suppress unused parameter warning */
    (void)buf_end;
    (void)ranges;
    (void)ranges_size;
#endif
    return buf;
}

static const char *get_token_to_eol(const char *buf, const char *buf_end, const char **token, size_t *token_len, size_t *ret)
{
    const char *token_start = buf;

#ifdef __SSE4_2__
    static const char ALIGNED(16) ranges1[16] = "\0\010"    /* allow HT */
                                                "\012\037"  /* allow SP and up to but not including DEL */
                                                "\177\177"; /* allow chars w. MSB set */
    int found;
    buf = find_char_fast(buf, buf_end, ranges1, 6, &found);
    if (found)
        goto FOUND_CTL;
#else
    /* find non-printable char within the next 8 bytes, this is the hottest code; manually inlined */
    while (buf_end - buf >= 8) {
#define DOIT()                                                                                                                     \
    do {                                                                                                                           \
        if (!IS_PRINTABLE_ASCII(*buf))                                                                                   \
            goto NonPrintable;                                                                                                     \
        ++buf;                                                                                                                     \
    } while (0)
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
        DOIT();
#undef DOIT
        continue;
        NonPrintable:
        if (((unsigned char)*buf < '\040' && *buf != '\011') || *buf == '\177') {
            goto FOUND_CTL;
        }
        ++buf;
    }
#endif
    for (;; ++buf) {
        CHECK_EOF()
        if (!IS_PRINTABLE_ASCII(*buf)) {
            if (((unsigned char)*buf < '\040' && *buf != '\011') || *buf == '\177') {
                goto FOUND_CTL;
            }
        }
    }
    FOUND_CTL:
    if (*buf == '\015') {
        ++buf;
        EXPECT_CHAR('\012')
        *token_len = buf - 2 - token_start;
    } else if (*buf == '\012') {
        *token_len = buf - token_start;
        ++buf;
    } else {
        *ret = -1;
        return NULL;
    }
    *token = token_start;

    return buf;
}

/* returned pointer is always within [buf, buf_end), or null */
static const char *parse_token(const char *buf, const char *buf_end, const char **token, size_t *token_len, char next_char,
                               size_t *ret)
{
    /* We use pcmpestri to detect non-token characters. This instruction can take no more than eight character ranges (8*2*8=128
     * bits that is the size of an SSE register). Due to this restriction, characters `|` and `~` are handled in the slow loop. */
    static const char ALIGNED(16) ranges[] = "\x00 "  /* control chars and up to SP */
                                             "\"\""   /* 0x22 */
                                             "()"     /* 0x28,0x29 */
                                             ",,"     /* 0x2c */
                                             "//"     /* 0x2f */
                                             ":@"     /* 0x3a-0x40 */
                                             "[]"     /* 0x5b-0x5d */
                                             "{\xff"; /* 0x7b-0xff */
    const char *buf_start = buf;
    int found;
    buf = find_char_fast(buf, buf_end, ranges, sizeof(ranges) - 1, &found);
    if (!found) {
        CHECK_EOF()
    }
    while (1) {
        if (*buf == next_char) {
            break;
        } else if (!token_char_map[(unsigned char)*buf]) {
            *ret = -1;
            return NULL;
        }
        ++buf;
        CHECK_EOF()
    }
    *token = buf_start;
    *token_len = buf - buf_start;
    return buf;
}

/* returned pointer is always within [buf, buf_end), or null */
static const char *parse_http_version(const char *buf, const char *buf_end, int *minor_version, size_t *ret)
{
    /* we want at least [HTTP/1.<two chars>] to try to parse */
    if (buf_end - buf < 9) {
        *ret = -2;
        return NULL;
    }
    EXPECT_CHAR_NO_CHECK('H')
    EXPECT_CHAR_NO_CHECK('T')
    EXPECT_CHAR_NO_CHECK('T')
    EXPECT_CHAR_NO_CHECK('P')
    EXPECT_CHAR_NO_CHECK('/')
    EXPECT_CHAR_NO_CHECK('1')
    EXPECT_CHAR_NO_CHECK('.')
    PARSE_INT(minor_version, 1)
    return buf;
}

// parse headers
static const char *parse_headers(const char *buf, const char *buf_end, struct http_header_t *headers, size_t *num_headers,
                                 size_t max_headers, size_t *ret)
{
    for (;; ++*num_headers) {
        CHECK_EOF()
        if (*buf == '\015') {
            ++buf;
            EXPECT_CHAR('\012')
            break;
        } else if (*buf == '\012') {
            ++buf;
            break;
        }
        if (*num_headers == max_headers) {
            *ret = -1;
            return NULL;
        }
        if (!(*num_headers != 0 && (*buf == ' ' || *buf == '\t'))) {
            /* parsing name, but do not discard SP before colon, see
             * http://www.mozilla.org/security/announce/2006/mfsa2006-33.html */
            if ((buf = parse_token(buf, buf_end, &headers[*num_headers].name, &headers[*num_headers].name_len, ':', ret)) == NULL) {
                return NULL;
            }
            if (headers[*num_headers].name_len == 0) {
                *ret = -1;
                return NULL;
            }
            ++buf;
            for (;; ++buf) {
                CHECK_EOF()
                if (!(*buf == ' ' || *buf == '\t')) {
                    break;
                }
            }
        } else {
            headers[*num_headers].name = NULL;
            headers[*num_headers].name_len = 0;
        }
        const char *value;
        size_t value_len;
        if ((buf = get_token_to_eol(buf, buf_end, &value, &value_len, ret)) == NULL) {
            return NULL;
        }
        /* remove trailing SPs and HTABs */
        const char *value_end = value + value_len;
        for (; value_end != value; --value_end) {
            const char c = *(value_end - 1);
            if (!(c == ' ' || c == '\t')) {
                break;
            }
        }
        headers[*num_headers].value = value;
        headers[*num_headers].value_len = value_end - value;
    }
    return buf;
}

// Parse http request line
static const char *parse_request_line(const char *buf, const char *buf_end, const char **method, size_t *method_len, const char **path,
                                 size_t *path_len, int *minor_version, struct http_header_t *headers, size_t *num_headers,
                                 size_t max_headers, size_t *ret)
{
    /* skip first empty line (some clients add CRLF after POST content) */
    CHECK_EOF()
    if (*buf == '\015') {
        ++buf;
        EXPECT_CHAR('\012')
    } else if (*buf == '\012') {
        ++buf;
    }

    /* parse request line */
    if ((buf = parse_token(buf, buf_end, method, method_len, ' ', ret)) == NULL) {
        return NULL;
    }
    do {
        ++buf;
        CHECK_EOF()
    } while (*buf == ' ');
    ADVANCE_TOKEN(*path, *path_len);
    do {
        ++buf;
        CHECK_EOF()
    } while (*buf == ' ');
    if (*method_len == 0 || *path_len == 0) {
        *ret = -1;
        return NULL;
    }
    if ((buf = parse_http_version(buf, buf_end, minor_version, ret)) == NULL) {
        return NULL;
    }
    if (*buf == '\015') {   // SI
        ++buf;
        EXPECT_CHAR('\012') // FF
    } else if (*buf == '\012') {
        ++buf;
    } else {
        *ret = -1;
        return NULL;
    }

    return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}

// Parse response line
static const char *parse_response_line(const char *buf, const char *buf_end, int *minor_version, int *status, const char **msg,
                                  size_t *msg_len, struct http_header_t *headers, size_t *num_headers, size_t max_headers, size_t *ret)
{
    /* parse "HTTP/1.x" */
    if ((buf = parse_http_version(buf, buf_end, minor_version, ret)) == NULL) {
        return NULL;
    }
    /* skip space */
    if (*buf != ' ') {
        *ret = -1;
        return NULL;
    }
    do {
        ++buf;
        CHECK_EOF()
    } while (*buf == ' ');
    /* parse status code, we want at least [:digit:][:digit:][:digit:]<other char> to try to parse */
    if (buf_end - buf < 4) {
        *ret = -2;
        return NULL;
    }
    PARSE_INT_3(status);

    /* get message including preceding space */
    if ((buf = get_token_to_eol(buf, buf_end, msg, msg_len, ret)) == NULL) {
        return NULL;
    }
    if (*msg_len == 0) {
        /* ok */
    } else if (**msg == ' ') {
        /* Remove preceding space. Successful return from `get_token_to_eol` guarantees that we would hit something other than SP
         * before running past the end of the given buffer. */
        do {
            ++*msg;
            --*msg_len;
        } while (**msg == ' ');
    } else {
        /* garbage found after status code */
        *ret = -1;
        return NULL;
    }

    return parse_headers(buf, buf_end, headers, num_headers, max_headers, ret);
}

// Parse http request header
static int parse_request_header(const char *buf_start, size_t len, const char **method, size_t *method_len, const char **path,
                              size_t *path_len, int *minor_version, struct http_header_t *headers, size_t *num_headers, size_t last_len)
{
    const char *buf = buf_start, *buf_end = buf_start + len;
    size_t max_headers = *num_headers;
    size_t r;

    *method = NULL;
    *method_len = 0;
    *path = NULL;
    *path_len = 0;
    *minor_version = -1;
    *num_headers = 0;

    /* if last_len != 0, check if the request is complete (a fast countermeasure
       againt slowloris */
    if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
        return r;
    }

    if ((buf = parse_request_line(buf, buf_end, method, method_len, path, path_len, minor_version, headers, num_headers, max_headers,
                             &r)) == NULL) {
        return r;
    }

    return (int)(buf - buf_start);
}

// Parse http response header
static int parse_response_header(const char *buf_start, size_t len, int *minor_version, int *status, const char **msg, size_t *msg_len,
                        struct http_header_t *headers, size_t *num_headers, size_t last_len)
{
    const char *buf = buf_start, *buf_end = buf + len;
    size_t max_headers = *num_headers;
    size_t r;

    *minor_version = -1;
    *status = 0;
    *msg = NULL;
    *msg_len = 0;
    *num_headers = 0;

    /* if last_len != 0, check if the response is complete (a fast countermeasure
       against slowloris */
    if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
        return r;
    }

    if ((buf = parse_response_line(buf, buf_end, minor_version, status, msg, msg_len, headers, num_headers, max_headers, &r)) == NULL) {
        return r;
    }

    return (int)(buf - buf_start);
}

size_t http_parse_request_headers(struct raw_data_s *raw_data, http_request *req)
{
    return parse_request_header(raw_data->data, raw_data->data_len, &req->method, &req->method_len,
                              &req->path, &req->path_len, &req->minor_version,
                              req->headers, &req->num_headers, /*last_len*/ 0);
}

size_t http_parse_response_headers(struct raw_data_s *raw_data, http_response *resp)
{
    return parse_response_header(raw_data->data, raw_data->data_len, &resp->minor_version, &resp->status,
                               &resp->msg, &resp->msg_len, resp->headers, &resp->num_headers, /*last_len*/ 0);
}

http_headers_map *get_http_headers_map(http_header *headers, size_t num_headers)
{
    http_headers_map *headers_map = init_http_headers_map();
    for (size_t i = 0; i < num_headers; i++) {
        char *name, *value;
        strcpy(name, headers[i].name);
        strcpy(value, headers[i].value);
        insert_into_multiple_map(headers_map, name, value);
    }
    return headers_map;
}

http_request *init_http_request(void)
{
    http_request *req = (http_request *) malloc(sizeof(http_request));
    if (req == NULL) {
        ERROR("[HTTP PARSER] Failed to malloc http_request.");
        return NULL;
    }
    return req;
}

void free_http_request(http_request *req)
{
    if (req == NULL) {
        return;
    }
    if (req->method != NULL) {
        free(req->method);
    }
    if (req->path != NULL) {
        free(req->path);
    }
    if (req->headers != NULL) {
        free_http_headers_map(req->headers);
    }
    free(req);
}

http_response *init_http_response(void)
{
    http_response *resp = (http_response *) malloc(sizeof(http_response));
    if (resp == NULL) {
        ERROR("[HTTP1.x PARSER] Failed to malloc http_response.");
        return NULL;
    }
    return resp;
}

void free_http_response(http_response *resp)
{
    if (resp == NULL) {
        return;
    }
    if (resp->msg !=NULL) {
        free(resp->msg);
    }
    if (resp->headers != NULL) {
        free_http_headers_map(resp->headers);
    }
    free(resp);
}