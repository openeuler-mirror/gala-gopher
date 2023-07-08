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

#define K_MAX_NUM_HEADERS 50

#ifdef _MSC_VER
#define ALIGNED(n) _declspec(align(n))
#else
#define ALIGNED(n) __attribute__((aligned(n)))
#endif

#define IS_PRINTABLE_ASCII(c) ((unsigned char)(c)-040u < 0137u)

// Check the buf is at the end, if end then return -2，NEEDS_MORE_DATA
#define CHECK_EOF()                                                                                                                \
    if (buf == buf_end) {                                                                                                          \
        *ret = -2;                                                                                                                 \
        return NULL;                                                                                                               \
    }

// Check the next char of buf is ch
#define EXPECT_CHAR_NO_CHECK(ch)                                                                                                   \
    if (*buf++ != ch) {                                                                                                            \
        *ret = -1;                                                                                                                 \
        return NULL;                                                                                                               \
    }

// Check if the char is expected 'ch', if not then return -1, Failed to parse
#define EXPECT_CHAR(ch)                                                                                                            \
    CHECK_EOF();                                                                                                                   \
    EXPECT_CHAR_NO_CHECK(ch);

// do once,
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

#define PARSE_INT(val, mul)                                                                                                     \
    if (*buf < '0' || '9' < *buf) {                                                                                                \
        buf++;                                                                                                                     \
        *ret = -1;                                                                                                                 \
        return NULL;                                                                                                               \
    }                                                                                                                              \
    *(val) = (mul) * (*buf++ - '0');

#define PARSE_INT_3(val)                                                                                                         \
    do {                                                                                                                           \
        int res = 0;                                                                                                              \
        PARSE_INT(&res_, 100)                                                                                                      \
        *val = res;                                                                                                             \
        PARSE_INT(&res_, 10)                                                                                                       \
        *val += res;                                                                                                            \
        PARSE_INT(&res_, 1)                                                                                                        \
        *val += res;                                                                                                            \
    } while (0)


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

// 解析token，返回已处理到的buf指针，范围在[buf, buf_end)之间
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

// 解析HTTP协议版本
static const char *parse_http_version(const char *buf, const char *buf_end, int *minor_version, size_t *ret)
{
    // 协议号有9个字符 [HTTP/1.<two chars>]
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

// 解析请求头，格式:
// field-name | : | [field-value] | CRLF
// field-name | : | [field-value] | CRLF
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

// 解析请求行，格式：Method | SP | Request-URI | SP | HTTP-Version | CRLF
static const char *parse_request_line(const char *buf, const char *buf_end, http_request *req, const size_t *ret)
{
    // 跳过空行，有些http客户端会在POST之后添加CRLF
    CHECK_EOF()
    if (*buf == '\015') {
        ++buf;
        EXPECT_CHAR('\012')
    } else if (*buf == '\012') {
        ++buf;
    }

    // 解析请求method
    buf = parse_token(buf, buf_end, &req->method, &req->method_len, ' ', &&ret);
    if (buf == NULL) {
        return NULL;
    }

    // 跳过空格
    do {
        ++buf;
        CHECK_EOF()
    } while (*buf == ' ');

    // 解析uri，即path
    ADVANCE_TOKEN(req->path, req->path_len);

    // 跳过空格
    do {
        ++buf;
        CHECK_EOF()
    } while (*buf == ' ');

    // 解析method或path失败时，返回-1报错
    if (req->method_len == 0 || req->path_len == 0) {
        *ret = -1;
        return NULL;
    }

    // 解析http版本号
    buf = parse_http_version(buf, buf_end, req->minor_version, &&ret);
    if (buf == NULL) {
        return NULL;
    }

    // 跳过行末终结符CRLF
    if (*buf == '\015') {
        ++buf;
        EXPECT_CHAR('\012')
    } else if (*buf == '\012') {
        ++buf;
    } else {
        *ret = -1;
        return NULL;
    }

    // 解析请求行
    return parse_headers(buf, buf_end, req->headers, &req->num_headers, K_MAX_NUM_HEADERS, &&ret);
}

// 解析响应行，格式：Http-Version | SP | Status-Code | SP | Reason-Phrase | CRLF
static const char *parse_response_line(const char *buf, const char *buf_end, http_response * resp, const size_t *ret)
{
    // 解析版本号 HTTP/1.x
    buf = parse_http_version(buf, buf_end, &resp->minor_version, &&ret)
    if ((buf) == NULL) {
        return NULL;
    }
    if (*buf != ' ') {
        *ret = -1;
        return NULL;
    }

    // 跳过空格SP
    do {
        ++buf;
        CHECK_EOF()
    } while (*buf == ' ');

    // 如果行末字符数小于4，则返回-2（needs more data），状态码3位 + CRLF 1位
    if (buf_end - buf < 4) {
        *ret = -2;
        return NULL;
    }

    // 解析状态码（3位数）
    PARSE_INT_3(resp->status);

    // 解析Reason-Phrase，放入resp->msg中
    buf = get_token_to_eol(buf, buf_end, &resp->msg, &resp->msg_len, ret);
    if (buf == NULL) {
        return NULL;
    }

    // msg为空时（即msg_len为0时）为正确场景，直接下一步解析响应头
    if (resp->msg_len == 0) {
        // 解析响应行
        return parse_headers(buf, buf_end, resp->headers, &resp->num_headers, K_MAX_NUM_HEADERS, ret);
    }

    // msg首字符为空格时，去除开头的所有空格
    if (*resp->msg == ' ') {
        do {
            ++resp->msg;
            --resp->msg_len;
        } while (*resp->msg == ' ');

        // 解析响应行
        return parse_headers(buf, buf_end, resp->headers, &resp->num_headers, K_MAX_NUM_HEADERS, ret);

    }

    // 如果不为以上两种情况，解析错误，返回-1
    *ret = -1;
    return NULL;
}

size_t http_parse_request_headers(struct raw_data_s *raw_data, http_request *req)
{
    size_t ret;
    const char *buf_start = raw_data->data + raw_data->current_pos;
    const char *buf_end = raw_data->data + raw_data->data_len;
    const char *buf = raw_data->data + raw_data->current_pos;

    // 解析请求行与请求头
    buf = parse_request_line(buf, buf_end, req, &ret);
//    buf = parse_request_line(buf, buf_end, &req->method, &req->method_len, &req->path, &req->path_len, &req->minor_version,
//                             req->headers, &req->num_headers, req->num_headers, &ret);
    if (buf == NULL) {
        return ret;
    }
    return (int)(buf - buf_start);
}

size_t http_parse_response_headers(struct raw_data_s *raw_data, http_response *resp)
{
    size_t ret;
    const char *buf_start = raw_data->data + raw_data->current_pos;
    const char *buf_end = raw_data->data + raw_data->data_len;
    const char *buf = raw_data->data + raw_data->current_pos;

    // 解析响应行和响应头
    buf = parse_response_line(buf, buf_end, resp, &ret);
//    buf = parse_response_line(buf, buf_end, &resp->minor_version, &resp->status, &resp->msg, &resp->msg_len, resp->headers,
//                              &resp->num_headers, resp->num_headers, &ret);
    if (buf == NULL) {
        return ret;
    }
    return (int)(buf - buf_start);
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

http_header *init_http_header()
{
    http_header *header = (http_header *) malloc(sizeof(http_header));
    if (header == NULL) {
        ERROR("[Http Parse] Failed to malloc http_header.");
        return NULL;
    }
    return header;
}

void free_http_header(http_header *header)
{
    if (header == NULL) {
        return;
    }
    free(header);
}

http_request *init_http_request(void)
{
    http_request *req = (http_request *) malloc(sizeof(http_request));
    if (req == NULL) {
        ERROR("[HTTP PARSER] Failed to malloc http_request.");
        return NULL;
    }
    req->method = NULL;
    req->method_len = 0;
    req->path = NULL;
    req->path_len = 0;
    req->minor_version = -1;
    req->num_headers = 0;
    req->headers = init_http_header();
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
        free_http_header(req->headers);
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
    resp->minor_version = -1;
    resp->status = 0;
    resp->msg = NULL;
    resp->msg_len = 0;
    resp->num_headers = 0;
    resp->headers = init_http_header();
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
        free_http_header(resp->headers);
    }
    free(resp);
}