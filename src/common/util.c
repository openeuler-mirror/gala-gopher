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
 * Author: sky
 * Create: 2021-05-22
 * Description: lib module
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include "common.h"

char *get_cur_date(void)
{
    /* return date str, ex: 2021/05/17 */
    static char tm[TM_STR_LEN] = {0};
    struct tm *tmp_ptr = NULL;
    time_t t;

    (void)time(&t);

    tmp_ptr = localtime(&t);
    (void)snprintf(tm,
        TM_STR_LEN,
        "%d-%02d-%02d",
        (1900 + tmp_ptr->tm_year),
        (1 + tmp_ptr->tm_mon),
        tmp_ptr->tm_mday);
    return tm;
}

char *get_cur_time(void)
{
    /* return time str, ex: 2021/05/17 19:56:03 */
    static char tm[TM_STR_LEN] = {0};
    struct tm *tmp_ptr = NULL;
    time_t t;

    (void)time(&t);

    tmp_ptr = localtime(&t);
    (void)snprintf(tm,
        TM_STR_LEN,
        "%d-%02d-%02d-%02d-%02d-%02d",
        (1900 + tmp_ptr->tm_year),
        (1 + tmp_ptr->tm_mon),
        tmp_ptr->tm_mday,
        tmp_ptr->tm_hour,
        tmp_ptr->tm_min,
        tmp_ptr->tm_sec);
    return tm;
}

void ip6_str(unsigned char *ip6, unsigned char *ip_str, unsigned int ip_str_size)
{
    unsigned short *addr = (unsigned short *)ip6;
    int i, j;
    char str[48];

    /*
      parse ipv4 from ipv6 if the ipv6_addr is ipv4_addr mapped
      eg: [0000...0000:ffff:192.168.1.23] -> [192.168.1.23]
     */
    if (NIP6_IS_ADDR_V4MAPPED(addr)) {
        (void)snprintf((char *)ip_str, ip_str_size, "%u.%u.%u.%u",
                       ip6[IP4_BYTE_1_IN_IP6], ip6[IP4_BYTE_2_IN_IP6], ip6[IP4_BYTE_3_IN_IP6], ip6[IP4_BYTE_4_IN_IP6]);
        return;
    }
    /* 1. format ipv6 address */
    (void)snprintf((char *)str, ip_str_size, NIP6_FMT, NIP6(addr));
    /* 2. compress */
    for (i = 0, j = 0; str[j] != '\0'; i++, j++) {
        if (str[j] == '0' && (j == 0 || ip_str[i - 1] == ':')) {  // the first 0
            if (str[j + 1] != '0') {        // 0XXX
                j = j + 1;
            } else if (str[j + 2]!='0') {   // 00XX
                j = j + 2;
            } else {                        // 000X 0000
                j = j + 3;
            }
        }
        ip_str[i] = str[j];
    }
    ip_str[i] = '\0';
    return;
}

void ip_str(unsigned int family, unsigned char *ip, unsigned char *ip_str, unsigned int ip_str_size)
{
    ip_str[0] = 0;

    if (family == AF_INET6) {
        (void)ip6_str(ip, ip_str, ip_str_size);
        return;
    }

    (void)snprintf((char *)ip_str, ip_str_size, "%u.%u.%u.%u",
                   ip[IP4_BYTE_1], ip[IP4_BYTE_2], ip[IP4_BYTE_3], ip[IP4_BYTE_4]);
    return;
}

void split_newline_symbol(char *s)
{
    int len = strlen(s);
    if (len > 0 && s[len - 1] == '\n') {
        s[len - 1] = 0;
    }
}

char is_exist_mod(const char *mod)
{
    int cnt = 0;
    FILE *fp;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, "lsmod | grep -w %s | wc -l", mod);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        return 0;
    }

    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, fp) != NULL) {
        SPLIT_NEWLINE_SYMBOL(line);
        cnt = atoi(line);
    }
    pclose(fp);

    return (char)(cnt > 0);
}

int exec_cmd(const char *cmd, char *buf, unsigned int buf_len)
{
    FILE *f = NULL;

    f = popen(cmd, "r");
    if (f == NULL)
        return -1;

    if (fgets(buf, buf_len, f) == NULL) {
        (void)pclose(f);
        return -1;
    }
    (void)pclose(f);

    SPLIT_NEWLINE_SYMBOL(buf);
    return 0;
}

int __snprintf(char **buf, const int bufLen, int *remainLen, const char *format, ...)
{
    int len;
    char *p = *buf;
    va_list args;

    if (bufLen <= 0) {
        return -1;
    }

    va_start(args, format);
    len = vsnprintf(p, (const unsigned int)bufLen, format, args);
    va_end(args);

    if (len >= bufLen || len < 0) {
        return -1;
    }

    *buf += len;
    *remainLen = bufLen - len;

    return 0;
}

char is_digit_str(const char *s)
{
    int len = (int)strlen(s);
    for (int i = 0; i < len; i++) {
        if (!(isdigit(s[i]))) {
            return 0;
        }
    }
    return 1;
}

int get_system_ip(char ip_str[], unsigned int size)
{
    const char *cmd = "/sbin/ip a | grep inet | grep -v \"127.0.0.1\" | grep -v inet6 | awk 'NR==1 {print $2}' |  awk -F '/' '{print $1}'";

    return exec_cmd(cmd, ip_str, size);
}

int get_comm(int pid, char comm_str[], unsigned int size)
{
    char proc_comm[PATH_LEN];
    char cat_proc_comm[PATH_LEN];
    const char *fmt1 = "/proc/%d/comm";
    const char *fmt2 = "/usr/bin/cat /proc/%d/comm";

    proc_comm[0] = 0;
    (void)snprintf(proc_comm, PATH_LEN, fmt1, pid);
    if (access((const char *)proc_comm, 0) != 0) {
        return -1;
    }

    cat_proc_comm[0] = 0;
    (void)snprintf(cat_proc_comm, PATH_LEN, fmt2, pid);
    return exec_cmd(cat_proc_comm, comm_str, size);
}

int get_proc_startup_ts(int pid)
{
    int ret;
    char proc_stat[PATH_LEN];
    char cat_proc_stat[PATH_LEN];
    char startup_ts[INT_LEN];
    const char *fmt1 = "/proc/%d/stat";
    const char *fmt2 = "/usr/bin/cat /proc/%d/stat | awk '{print $22}'";

    proc_stat[0] = 0;
    (void)snprintf(proc_stat, PATH_LEN, fmt1, pid);
    if (access((const char *)proc_stat, 0) != 0) {
        return -1;
    }

    cat_proc_stat[0] = 0;
    startup_ts[0] = 0;
    (void)snprintf(cat_proc_stat, PATH_LEN, fmt2, pid);
    ret = exec_cmd(cat_proc_stat, startup_ts, INT_LEN);
    if (ret) {
        return -1;
    }

    return atoi(startup_ts);
}

int get_system_uuid(char *buffer, unsigned int size)
{
    FILE *fp = NULL;

    fp = popen("dmidecode -s system-uuid | tr 'A-Z' 'a-z'", "r");
    if (fp == NULL) {
        return -1;
    }

    if (fgets(buffer, (int)size, fp) == NULL) {
        pclose(fp);
        return -1;
    }
    if (strlen(buffer) > 0 && buffer[strlen(buffer) - 1] == '\n') {
        buffer[strlen(buffer) - 1] = '\0';
    }

    pclose(fp);
    return 0;
}

int copy_file(const char *dst_file, const char *src_file) {
    FILE *fp1 = fopen(dst_file, "w");
    if (fp1 == NULL) {
        return -1;
    }
    FILE *fp2 = fopen(src_file, "r");
    if(fp2 == NULL) {
        fclose(fp1);
        return -1;
    }

    void *buffer = (void *)malloc(2);
    while (1) {
        int op = fread(buffer, 1, 1, fp2);
        if(!op) {
            break;
        }
        fwrite(buffer, 1, 1, fp1);
    }

    free(buffer);
    fclose(fp1);
    fclose(fp2);
    return 0;
}