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
#include <limits.h>
#include <regex.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "common.h"

#define CHROOT_CMD          "/usr/sbin/chroot %s %s"
#define PROC_COMM           "/proc/%u/comm"
#define PROC_COMM_CMD       "/usr/bin/cat /proc/%u/comm 2> /dev/null"
#define PROC_CMDLINE        "/proc/%u/cmdline"
#define PROC_STR_CMDLINE    "/proc/%s/cmdline"
#define PROC_EXE_CMD        "/usr/bin/readlink /proc/%u/exe 2> /dev/null"
#define PROC_STAT           "/proc/%u/stat"
#define PROC_START_TIME_CMD "/usr/bin/cat /proc/%u/stat | awk '{print $22}'"
#define SYS_UUID_CMD        "/usr/bin/cat /sys/class/dmi/id/product_uuid"
#define SYS_UUID_CMD_ALT    "/usr/bin/cat /opt/gala-gopher/machine_id"
#define SYS_HOSTNAME_CMD    "/usr/bin/uname -n"
#define PROC_MAPS_PATH      "/proc/%d/maps"

static char *g_host_path_prefix;

static char *get_host_path_prefix(void)
{
    static char running_in_container = 1;

    /* gala-gopher running on host */
    if (running_in_container == 0) {
        return NULL;
    }

    if (g_host_path_prefix) {
        return g_host_path_prefix;
    }

    /* env HOST_PATH_PREFIX_ENV is set means gala-gopher is running in container */
    g_host_path_prefix = getenv(HOST_PATH_PREFIX_ENV);
    if (g_host_path_prefix) {
        return g_host_path_prefix;
    }

    running_in_container = 0;
    return NULL;
}

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

static void ip6_str(unsigned char *ip6, unsigned char *ip_str, unsigned int ip_str_size)
{
    unsigned short *addr = (unsigned short *)ip6;

    /*
      parse ipv4 from ipv6 if the ipv6_addr is ipv4_addr mapped
      eg: [0000...0000:ffff:192.168.1.23] -> [192.168.1.23]
     */
    if (NIP6_IS_ADDR_V4MAPPED(addr)) {
        (void)snprintf((char *)ip_str, ip_str_size, "%u.%u.%u.%u",
                       ip6[IP4_BYTE_1_IN_IP6], ip6[IP4_BYTE_2_IN_IP6], ip6[IP4_BYTE_3_IN_IP6], ip6[IP4_BYTE_4_IN_IP6]);
        return;
    }

    inet_ntop(AF_INET6, (const void *)ip6, (char *)ip_str, ip_str_size);
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
    size_t len = strlen(s);
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
        cnt = strtol(line, NULL, 10);
    }
    pclose(fp);

    return (char)(cnt > 0);
}

const char *get_cmd_chroot(const char *orig_cmd, char *chroot_cmd, unsigned int buf_len)
{
    char *host_path = get_host_path_prefix();
    if (orig_cmd == NULL || host_path == NULL) {
        return orig_cmd;
    }

    chroot_cmd[0] = 0;
    (void)snprintf(chroot_cmd, buf_len, CHROOT_CMD, host_path, orig_cmd);
    return chroot_cmd;
}

void *popen_chroot(const char *command, const char *modes) {
    char *host_path = get_host_path_prefix();
    char chroot_cmd[CHROOT_COMMAND_LEN];

    if (host_path) {
        chroot_cmd[0] = 0;
        (void)snprintf(chroot_cmd, CHROOT_COMMAND_LEN, CHROOT_CMD, host_path, command);
        command = chroot_cmd;
    }

    return popen(command, modes);
}

int exec_cmd_chroot(const char *cmd, char *buf, unsigned int buf_len)
{
    FILE *f = NULL;

    f = popen_chroot(cmd, "r");
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

    return exec_cmd_chroot(cmd, ip_str, size);
}

int get_system_uuid(char *buffer, unsigned int size)
{
    if (exec_cmd_chroot(SYS_UUID_CMD, buffer, size)) {
        return exec_cmd_chroot(SYS_UUID_CMD_ALT, buffer, size);
    }

    return 0;
}

int get_system_hostname(char *buf, unsigned int size)
{
    return exec_cmd_chroot(SYS_HOSTNAME_CMD, buf, size);
}

int copy_file(const char *dst_file, const char *src_file)
{
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
    if (buffer == NULL) {
        fclose(fp1);
        fclose(fp2);
        return -1;
    }

    while (1) {
        size_t op = fread(buffer, 1, 1, fp2);
        if(op == 0) {
            break;
        }
        (void)fwrite(buffer, 1, 1, fp1);
    }

    free(buffer);
    fclose(fp1);
    fclose(fp2);
    return 0;
}

int access_check_read_line(u32 pid, const char *command, const char *fname, char *buf, u32 buf_len)
{
    char fname_cmd[LINE_BUF_LEN];
    char cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];

    fname_cmd[0] = 0;
    (void)snprintf(fname_cmd, LINE_BUF_LEN, fname, pid);
    if (access((const char *)fname_cmd, 0) != 0) {
        return -1;
    }

    cmd[0] = 0;
    line[0] = 0;
    (void)snprintf(cmd, LINE_BUF_LEN, command, pid);
    if (exec_cmd(cmd, line, LINE_BUF_LEN) != 0) {
        ERROR("[SYSTEM_PROBE] proc get_info fail, line is null.\n");
        return -1;
    }

    (void)snprintf(buf, buf_len, "%s", line);
    return 0;
}

static int read_starttime_from_procstat(char *line, char *buf, int buf_len) {
    int ret;
    char *pos, *space_pos;
    const char *space_chrs = " \t";
    int idx = 1;

#define __PROC_STAT_STARTTIME_IDX 22
    pos = line + strspn(line, space_chrs);
    while ((space_pos = strpbrk(pos, space_chrs)) != NULL) {
        if (idx == __PROC_STAT_STARTTIME_IDX) {
            *space_pos = '\0';
            ret = snprintf(buf, buf_len, "%s", pos);
            if (ret < 0 || ret >= buf_len) {
                return -1;
            }
            return 0;
        }
        idx++;
        pos = space_pos + strspn(space_pos, space_chrs);
    }
    return -1;
}

int get_proc_start_time(u32 pid, char *buf, int buf_len)
{
    FILE *f = NULL;
    char fname[PATH_LEN];
    char line[LINE_BUF_LEN];

    fname[0] = 0;
    (void)snprintf(fname, sizeof(fname), PROC_STAT, pid);
    f = fopen(fname, "r");
    if (!f) {
        return -1;
    }
    line[0] = 0;
    if (fgets(line, sizeof(line), f) == NULL) {
        (void)fclose(f);
        return -1;
    }
    (void)fclose(f);

    return read_starttime_from_procstat(line, buf, buf_len);
}

#define PROC_PID_STAT           "/proc/%s/stat"
u64 get_proc_startup_ts(const char *pid)
{
    struct stat st;
    char fname[PATH_LEN];

    fname[0] = 0;
    (void)snprintf(fname, sizeof(fname), PROC_PID_STAT, pid);
    if (stat(fname, &st) == 0) {
        return st.st_ctime;
    }

    return 0;
}

int get_proc_comm(u32 pid, char *buf, int buf_len)
{
    return access_check_read_line(pid, PROC_COMM_CMD, PROC_COMM, buf, buf_len);
}

int get_proc_cmdline(u32 pid, char *buf, u32 buf_len)
{
    FILE *f = NULL;
    char path[LINE_BUF_LEN];
    u32 index = 0;

    (void)memset(buf, 0, buf_len);

    path[0] = 0;
    (void)snprintf(path, LINE_BUF_LEN, PROC_CMDLINE, pid);
    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    /* parse line */
    while (feof(f) == 0) {
        if (index >= buf_len - 1) {
            buf[buf_len - 1] = '\0';
            break;
        }
        buf[index] = fgetc(f);
        if (buf[index] == '\"') {
            if (index > buf_len - 2) {
                buf[index] = '\0';
                break;
            } else {
                buf[index] = '\\';
                buf[index + 1] =  '\"';
                index++;
            }
        } else if (buf[index] == '\0') {
            buf[index] = ' ';
        } else if ((unsigned char)buf[index] == (unsigned char)EOF) {
            buf[index] = '\0';
        }
        index++;
    }

    (void)fclose(f);
    return 0;
}

int get_proc_str_cmdline(const char *pid_str, char *buf, u32 buf_len)
{
    FILE *f = NULL;
    char path[LINE_BUF_LEN];
    int index = 0;

    path[0] = 0;
    (void)snprintf(path, LINE_BUF_LEN, PROC_STR_CMDLINE, pid_str);
    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    /* parse line */
    while (!feof(f)) {
        if (index >= buf_len - 1) {
            buf[buf_len - 1] = '\0';
            break;
        }
        buf[index] = fgetc(f);
        if (buf[index] == '\"') {
            if (index > buf_len - 2) {
                buf[index] = '\0';
                break;
            } else {
                buf[index] = '\\';
                buf[index + 1] =  '\"';
                index++;
            }
        } else if (buf[index] == '\0') {
            buf[index] = ' ';
        } else if ((unsigned char)buf[index] == (unsigned char)EOF) {
            buf[index] = '\0';
        }
        index++;
    }

    buf[index] = 0;

    (void)fclose(f);
    return 0;
}

int get_proc_exe(u32 pid, char *buf, u32 buf_len)
{
    char cmd[PATH_LEN];

    cmd[0] = 0;
    (void)snprintf(cmd, sizeof(cmd), PROC_EXE_CMD, pid);
    return exec_cmd(cmd, buf, buf_len);
}

int get_so_path(int pid, char *elf_path, int size, const char *so_keyword)
{
    char map_file[PATH_LEN];
    char so_path[PATH_LEN];
    char *so_name;
    char buf[PATH_LEN];
    FILE *fp;
    int ret;

    elf_path[0] = 0;
    map_file[0] = 0;
    (void)snprintf(map_file, sizeof(map_file), PROC_MAPS_PATH, pid);
    fp = fopen(map_file, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        so_path[0] = 0;
        if (sscanf(buf, "%*x-%*x %*s %*s %*s %*s %255s", so_path) != 1) {
            continue;
        }
        if (so_path[0] != '/') {
            continue;
        }
        so_name = strrchr(so_path, '/') + 1;
        if (!strstr(so_name, so_keyword)) {
            continue;
        }
        ret = snprintf(elf_path, size, "/proc/%d/root%s", pid, so_path);
        if (ret < 0 || ret >= size) {
            break;
        }
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return -1;
}

int get_kern_version(u32 *kern_version)
{
    char major, minor, patch = 0;

    char version[INT_LEN];
    const char *major_cmd = "uname -r | awk -F '.' '{print $1}' 2>/dev/null";
    const char *minor_cmd = "uname -r | awk -F '.' '{print $2}' 2>/dev/null";

    version[0] = 0;
    if (exec_cmd(major_cmd, version, INT_LEN)) {
        return -1;
    }
    major = (char)strtol(version, NULL, 10);

    version[0] = 0;
    if (exec_cmd(minor_cmd, version, INT_LEN)) {
        return -1;
    }

    minor = (char)strtol(version, NULL, 10);

    *kern_version = (u32)KERNEL_VERSION(major, minor, patch);
    return 0;
}

int is_valid_proc(int pid)
{
    char fname[LINE_BUF_LEN];
    fname[0] = 0;

    (void)snprintf(fname, LINE_BUF_LEN, "/proc/%d", pid);
    if (access((const char *)fname, 0) == 0) {
        return 1;
    }
    return 0;
}

/*
 * Convert path to the relative host path mounted in the container by adding
 * a prefix dir(env "HOST_PATH_PREFIX_ENV").
 * @host_path: converted output which stored in
 * @path: original abs path
 * @path_len: len of host_path
 */
void convert_to_host_path(char *host_path, const char *path, int path_len)
{
    char *host_prefix;

    if (path == NULL || strlen(path) == 0) {
        return;
    }

    host_path[0] = 0;
    host_prefix = get_host_path_prefix();
    if (host_prefix) {
        (void)snprintf(host_path, path_len, "%s%s", host_prefix, path);
    } else {
        (void)snprintf(host_path, path_len, "%s", path);
    }

    DEBUG("convert path[%s] to host_path[%s]\n", path, host_path);
}

/*
 * Check the path to avoid command injection
 * @path: path executed as command
 */
int check_path_for_security(const char *path)
{
    char *command_injection_characters[] = {"|", ";", "&", "$", ">", "<", "(", ")", "./", "/.", "?", "*",
                                    "\'", "`", "[", "]", "\\", "!", "\n"};

    if (path == NULL || strlen(path) == 0) {
        return 0;
    }

    size_t command_injection_characters_len = sizeof(command_injection_characters) /
        sizeof(command_injection_characters[0]);

    for (int i = 0; i < command_injection_characters_len; ++i) {
        if (strstr(path, command_injection_characters[i])) {
            return 1;
        }
    }

    return 0;
}

int regex_pattern_matched(const char *conf_pattern, const char *target)
{
    int status;
    regex_t re;

    if (target[0] == 0 || conf_pattern[0] == 0) {
        return 0;
    }

    if (regcomp(&re, conf_pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        return 0;
    }

    status = regexec(&re, target, 0, NULL, 0);
    regfree(&re);

    return (status == 0) ? 1 : 0;
}