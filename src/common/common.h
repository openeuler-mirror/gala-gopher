/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Mr.lu
 * Create: 2022-5-30
 * Description: common macro define
 ******************************************************************************/
#ifndef __GOPHER_COMMON_H__
#define __GOPHER_COMMON_H__

#pragma once

#ifndef AF_INET
#define AF_INET     2   /* Internet IP Protocol */
#endif
#ifndef AF_INET6
#define AF_INET6    10  /* IP version 6 */
#endif

#define INT_LEN                 32
#define THOUSAND                1000
#define PATH_NUM                20
#define IP_LEN                  4
#define IP_STR_LEN              128
#define IP6_LEN                 16
#define IP6_STR_LEN             128

#define IP4_BYTE_1              0
#define IP4_BYTE_2              1
#define IP4_BYTE_3              2
#define IP4_BYTE_4              3
#define IP4_BYTE_1_IN_IP6       12
#define IP4_BYTE_2_IN_IP6       13
#define IP4_BYTE_3_IN_IP6       14
#define IP4_BYTE_4_IN_IP6       15

#define TM_STR_LEN              48

#define TASK_COMM_LEN           16
#define PROC_CMDLINE_LEN        128
#define MAX_PROCESS_NAME_LEN    32
#define TASK_EXE_FILE_LEN       128
#define JAVA_COMMAND_LEN        128
#define JAVA_CLASSPATH_LEN      512

#define CONTAINER_NAME_LEN      64
#define CONTAINER_ID_LEN        64
#define CONTAINER_ABBR_ID_LEN   12
#define NAMESPACE_LEN           64
#define POD_NAME_LEN            64
#define TGID_LEN                10

#define COMMAND_LEN             256
#define LINE_BUF_LEN            512
#define PATH_LEN                256

#if !defined INET6_ADDRSTRLEN
    #define INET6_ADDRSTRLEN    48
#endif

#if !defined DISK_NAME_LEN
    #define DISK_NAME_LEN       32
#endif

#if !defined TIME_STRING_LEN
    #define TIME_STRING_LEN     32
#endif

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH    127
#endif

void debug_logs(const char* format, ...);
void info_logs(const char* format, ...);
void warn_logs(const char* format, ...);
void error_logs(const char* format, ...);

#ifndef GOPHER_DEBUG
static inline int __debug_printf(const char *format, ...)
{
        return 0; // NOTHING TO DO...
}
#define DEBUG (void)__debug_printf
#else
#define DEBUG debug_logs
#endif
#define INFO info_logs
#define WARN warn_logs
#define ERROR error_logs

#define max(x, y) ((x) > (y) ? (x) : (y))
#define min(x, y) ((x) < (y) ? (x) : (y))
#define min_zero(x, y) ((x) == 0 ? (y) : (((x) < (y) ? (x) : (y))))

#define __maybe_unused      __attribute__((unused))

#define HZ 100

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

#ifndef NULL
#define NULL (void *)0
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef MAX_CPU
#define MAX_CPU 128
#endif

#define NS(sec)  ((__u64)(sec) * 1000000000)

#ifndef __u8
typedef unsigned char __u8;
typedef __u8 u8;
#endif

#ifndef __s8
typedef signed char __s8;
typedef __s8 s8;
#endif

#ifndef __s16
typedef signed short __s16;
typedef __s16 s16;
#endif

#ifndef __u16
typedef short unsigned int __u16;
typedef __u16 u16;
typedef __u16 __be16;
#endif

#ifndef __u32
typedef unsigned int __u32;
typedef __u32 u32;
typedef __u32 __be32;
typedef __u32 __wsum;
#endif

#ifndef __s64
typedef long long int __s64;
typedef __s64 s64;
#endif

#ifndef __u64
typedef long long unsigned int __u64;
typedef __u64 u64;
#endif


void split_newline_symbol(char *s);
#define SPLIT_NEWLINE_SYMBOL(s)     split_newline_symbol(s)

#ifndef ntohs
unsigned short ntohs(unsigned short netshort);
#endif

#define NIP6(addr) \
    ntohs((addr)[0]), ntohs(addr[1]), ntohs(addr[2]), ntohs(addr[3]), ntohs(addr[4]), ntohs(addr[5]), \
    (ntohs((addr)[6]) >> 8), (ntohs(addr[6]) & 0xff), (ntohs(addr[7]) >> 8), (ntohs(addr[7]) & 0xff)
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%u.%u.%u.%u"

#define NIP6_IS_ADDR_V4MAPPED(addr) \
    (((addr)[0] == 0) && \
    ((addr)[1] == 0) && \
    ((addr)[2] == 0) && \
    ((addr)[3] == 0) && \
    ((addr)[4] == 0) && \
    ((addr)[5] == 0xffff))

/* get uprobe func offset */
int get_func_offset(char *proc_name, char *func_name, char *bin_file_path);

char *get_cur_date(void);
char *get_cur_time(void);

void ip_str(unsigned int family, unsigned char *ip, unsigned char *ip_str, unsigned int ip_str_size);
int exec_cmd(const char *cmd, char *buf, unsigned int buf_len);
char is_exist_mod(const char *mod);
int __snprintf(char **buf, const int bufLen, int *remainLen, const char *format, ...);
char is_digit_str(const char *s);
int get_system_uuid(char *buffer, unsigned int size);
int copy_file(const char *dst_file, const char *src_file);

#endif
