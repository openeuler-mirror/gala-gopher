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
 * Author: wo_cow
 * Create: 2022-12-09
 * Description: java support for stackprobe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <sys/file.h>

#include "common.h"
#include "java_support.h"


#define NS_PATH_LEN 128
struct jvm_process_info {
    uid_t eUid;
    gid_t eGid;
    int nspid;
    int ns_changed;
    char ns_java_data_path[NS_PATH_LEN];    // /tmp/java-data-<pid>
    char ns_agent_path[NS_PATH_LEN];        // /tmp/jvm_agent.so | /tmp/jvmProbeAgent.jar
    char host_proc_dir[PATH_LEN];       // /proc/<pid>/root
    char host_java_tmp_file[PATH_LEN];  // /proc/<pid>/root/tmp/java-data-<pid>/java-symbols.bin | proc/<pid>/root/tmp/java-data-<pid>/jvm-metrics.txt
};

static char jvm_agent_file[FILENAME_LEN];
static char attach_type[ATTACH_TYPE_LEN];   // start | stop

#define ATTACH_BIN_PATH "/opt/gala-gopher/lib/jvm_attach"
#define HOST_SO_DIR "/opt/gala-gopher/extend_probes"
#define FIND_JAVA_SYM_CMD \
    "find /proc/%u/root/tmp/java-data-%u -type f -not -name " JAVA_SYM_FILE " -name \"java-symbols*.bin\" -delete"
#define HOST_JAVA_TMP_PATH "/proc/%u/root/tmp/java-data-%u/%s"  // eg: /proc/<pid>/root/tmp/java-data-<pid>/java-symbols.bin
#define NS_TMP_DIR "/tmp"

/*
    [root@localhost ~]# cat /proc/<pid>/status
    Name:   java
    ...
    Uid:    0       <eUid>       0       0
    Gid:    0       <eGid>       0       0
    NStgid: <pid>   <inner_pid>  <inner_inner_pid>
*/
static int _set_effective_id(int pid, struct jvm_process_info *v)
{
    uid_t cur_uid = geteuid();
    gid_t cur_gid = getegid();
    uid_t eUid = cur_uid;
    gid_t eGid = cur_gid;
    char path[64];
    int nspid = pid;
    int ret = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* status_file = fopen(path, "r");
    if (status_file == NULL) {
        goto out;
    }

    int nspid_found = 0;
    char* line = NULL;
    size_t size;
    while (getline(&line, &size, status_file) != -1) {
        if (strncmp(line, "Uid:", 4) == 0 && strtok(line + 4, "\t ") != NULL) {
            eUid = (uid_t)atoi(strtok(NULL, "\t "));
        } else if (strncmp(line, "Gid:", 4) == 0 && strtok(line + 4, "\t ") != NULL) {
            eGid = (gid_t)atoi(strtok(NULL, "\t "));
        } else if (strncmp(line, "NStgid:", 7) == 0) {
            char* s;
            for (s = strtok(line + 7, "\t "); s != NULL; s = strtok(NULL, "\t ")) {
                nspid = atoi(s);
            }
            nspid_found = 1;
        }
    }

    if (nspid_found == 0) {
        ret = -1;
    }

    if (pid != nspid) {
        v->ns_changed = 1;
    }

    if (line != NULL) {
        free(line);
    }
    fclose(status_file);
out:
    v->eGid = eGid;
    v->eUid = eUid;
    v->nspid = nspid;

    return ret;
}

static int __mkdir(char dst_dir[])
{
    if (access(dst_dir, F_OK) == 0) {
        return 0;
    }
    FILE *fp;
    char command[LINE_BUF_LEN];
    command[0] = 0;
    (void)snprintf(command, LINE_BUF_LEN, "/usr/bin/mkdir -p %s", dst_dir);
    fp = popen(command, "r");
    if (fp == NULL) {
        return -1;
    }
    (void)pclose(fp);
    return 0;
}

int set_ns_java_data_dir(u32 pid, char *ns_java_data_path, int path_len)
{
    if (ns_java_data_path == NULL || path_len <= 0) {
        return -1;
    }

    int ret = snprintf(ns_java_data_path, path_len, "/tmp/java-data-%u", pid);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

/*
    https://github.com/frohoff/jdk8u-jdk/blob/master/src/share/classes/sun/tools/attach/HotSpotVirtualMachine.java
    private void loadAgentLibrary()
    InputStream in = execute("load",
                                agentLibrary,
                                isAbsolute ? "true" : "false",
                                options);
*/
static int _set_attach_argv(u32 pid, struct jvm_process_info *v)
{
    int ret = 0;

    char *host_proc_dir = v->host_proc_dir;
    (void)snprintf(host_proc_dir, PATH_LEN, "/proc/%u/root", pid);
    ret = __mkdir(host_proc_dir);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: proc %u mkdir fail when copy agent so\n", pid);
        return ret;
    }

    char *ns_agent_path = v->ns_agent_path;
    (void)snprintf(ns_agent_path, NS_PATH_LEN, "%s/%s", NS_TMP_DIR, jvm_agent_file);
    char host_agent_file_path[LINE_BUF_LEN];
    (void)snprintf(host_agent_file_path, LINE_BUF_LEN, "%s%s", v->host_proc_dir, ns_agent_path);

    if ((access(host_agent_file_path, 0) != 0)) {
        char src_agent_file[PATH_LEN] = {0};
        (void)snprintf(src_agent_file, PATH_LEN, "%s/%s", HOST_SO_DIR, jvm_agent_file);
        ret = copy_file(host_agent_file_path, src_agent_file); // overwrite is ok.
        if (ret != 0) {
            ERROR("[JAVA_SUPPORT]: proc %u copy %s from %s file fail \n", pid, host_agent_file_path, src_agent_file);
            return ret;
        }
    }

    ret = chown(host_agent_file_path, v->eUid, v->eGid);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: chown %s to %u %u fail when set ns_agent_path\n",
              host_agent_file_path, v->eUid, v->eGid);
        return ret;
    }

    set_ns_java_data_dir(pid, v->ns_java_data_path, NS_PATH_LEN);

    char host_java_data_dir[LINE_BUF_LEN];
    host_java_data_dir[0] = 0;
    (void)snprintf(host_java_data_dir, LINE_BUF_LEN, "%s%s", v->host_proc_dir, v->ns_java_data_path);
    ret = __mkdir(host_java_data_dir);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: proc %u mkdir fail when set host_java_data_dir\n", pid);
        return ret;
    }
    ret = chown(host_java_data_dir, v->eUid, v->eGid);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: proc %u chown fail when set ns_java_data_path\n", pid);
        return ret;
    }

    return ret;
}

int get_host_java_tmp_file(u32 pid, const char *file_name, char *file_path, int path_len)
{
    if (file_path == NULL || path_len <= 0) {
        return -1;
    }

    // TODO: add start_time_ticks?
    (void)snprintf(file_path, path_len, HOST_JAVA_TMP_PATH, pid, pid, file_name);
    if (access(file_path, F_OK) != 0) {
        return -1;
    }

    return 0;
}

int detect_proc_is_java(u32 pid, char *comm, int comm_len)
{
    int is_java = 0;

    if (get_proc_comm(pid, comm, comm_len) != 0) {
        return 0;
    }

    if (strcmp(comm, "java") == 0) {
        is_java = 1;
    }

    return is_java;
}

/*
   In container scenario, it's necessary to set to the namespace of the container
   when attaching. Yet a multi-threaded process may not change user namespace with setns().
   Therefore, we have to do attach in the child process (because the stackprobe process is multi-threaded).
*/
static int _exe_attach_cmd(char *cmd)
{
    char result_buf[LINE_BUF_LEN];
    FILE *f = popen(cmd, "r");
    if (f == NULL) {
        ERROR("[JAVA_SUPPORT]: attach fail, popen error.\n");
        return -1;
    }
    DEBUG("[JAVA_SUPPORT]: do attach %s\n", cmd);
    while(fgets(result_buf, sizeof(result_buf), f) != NULL) {
        DEBUG("%s\n", result_buf);
        /* 判断load指令执行返回结果，非0表示失败 */
        if (isdigit(result_buf[0]) && atoi(result_buf) != 0) {
            ERROR("[JAVA_SUPPORT]: attach failed, cmd: %s, ret code: %s\n", cmd, result_buf);
            (void)pclose(f);
            return -1;
        }
    }
    (void)pclose(f);
    return 0;
}

static int _do_attach(u32 pid, const struct jvm_process_info *v)
{
    char cmd[LINE_BUF_LEN] = {0};
    char args[LINE_BUF_LEN] = {0};

    if (strstr(jvm_agent_file, ".so")) {
        // jvm_attach <pid> <nspid> load /tmp/xxxx.so true /tmp/java-data-<pid>,start
        if (strlen(attach_type) > 0) {
            (void)snprintf(args, LINE_BUF_LEN, "%s,%s",
                v->ns_java_data_path,
                attach_type);
        } else {
            (void)snprintf(args, LINE_BUF_LEN, "%s",
                v->ns_java_data_path);
        }
        (void)snprintf(cmd, LINE_BUF_LEN, "%s %d %d load %s true %s",
            ATTACH_BIN_PATH,
            pid,
            v->nspid,
            v->ns_agent_path,
            args);
    } else if (strstr(jvm_agent_file, ".jar")) {
        // jvm_attach <pid> <nspid> load instrument false "/tmp/xxxxx.jar=<pid>,/tmp/java-data-<pid>,start"
        if (strlen(attach_type) > 0) {
            (void)snprintf(args, LINE_BUF_LEN, "%u,%s,%s",
                pid,
                v->ns_java_data_path,
                attach_type);
        } else {
            (void)snprintf(args, LINE_BUF_LEN, "%u,%s",
                pid,
                v->ns_java_data_path);
        }
        (void)snprintf(cmd, LINE_BUF_LEN, "%s %u %d load instrument false \"%s=%s\"",
            ATTACH_BIN_PATH,
            pid,
            v->nspid,
            v->ns_agent_path,
            args);
    } else {
        ERROR("[JAVA_SUPPORT]: invalid jvm_agent_file input, return.\n");
        return -1;
    }

    return _exe_attach_cmd(cmd);
}

// The agent cannot actually be offloaded, so we delete the JAVA_SYM_FILE of other versions.
void java_offload_jvm_agent(u32 pid)
{
    char cmd[COMMAND_LEN];
    FILE *fp = NULL;

    cmd[0] = 0;
    (void)snprintf(cmd, sizeof(cmd), FIND_JAVA_SYM_CMD, pid, pid);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        ERROR("[JAVA_SUPPORT]: failed to execute: %s\n", cmd);
        return;
    }

    (void)pclose(fp);
    return;
}

int java_load(u32 pid, struct java_attach_args *args)
{
    struct jvm_process_info v = {0};

    (void)snprintf(jvm_agent_file, FILENAME_LEN, "%s", args->agent_file_name);

    if (strlen(args->action) > 0) {
        (void)snprintf(attach_type, ATTACH_TYPE_LEN, "%s", args->action);
    } else {
        attach_type[0] = 0;
    }

    if (!is_valid_proc(pid)) {
        WARN("[JAVA_SUPPORT] java_load to proc: %d break because proc is invalid.\n", pid);
        return -1;
    }
    (void)_set_effective_id(pid, &v);
    if (_set_attach_argv(pid, &v) != 0) {
        return -1;
    }
    if (_do_attach(pid, &v) != 0) {
        return -1;
    }

    return 0;
}

void java_msg_handler(u32 pid, struct java_attach_args *args, java_msg_handler_cb cb, void *cb_ctx)
{
    char tmp_file_path[PATH_LEN];

    tmp_file_path[0] = 0;
    if (get_host_java_tmp_file(pid, args->tmp_file_name, tmp_file_path, PATH_LEN) < 0) {
        DEBUG("[JAVA_MSG_HANDLER]: get_host_java_tmp_file %u failed.\n", pid);
        return;
    }

    int fd = open(tmp_file_path, O_RDWR);
    if (fd < 0) {
        DEBUG("[JAVA_MSG_HANDLER]: open tmp file: %s failed.\n", tmp_file_path);
        return;
    }
    if (lockf(fd, F_LOCK, 0) != 0) {
        DEBUG("[JAVA_MSG_HANDLER]: lockf tmpfile failed.\n");
        close(fd);
        return;
    }
    FILE *fp = fdopen(fd, "r");
    if (fp == NULL) {
        DEBUG("[JAVA_MSG_HANDLER]: fopen tmp file: %s failed.\n", tmp_file_path);
        close(fd);
        return;
    }

    if (!cb) {
        char line[LINE_BUF_LEN];
        line[0] = 0;
        while (fgets(line, LINE_BUF_LEN, fp) != NULL) {
            (void)fprintf(stdout, "%s", line);
            line[0] = 0;
        }
    } else {
        struct file_ref_s file_ref = {.pid = pid, .fd = fd, .fp = fp};
        cb(cb_ctx, &file_ref);
    }

    (void)fflush(stdout);
    if (ftruncate(fd, 0)) {
        DEBUG("[JAVA_SUPPORT]: ftruncate file: %s failed.\n", tmp_file_path);
    }
    (void)fclose(fp);

    return;
}

#define KW_MAIN_CLASS_NAME "sun.java.command="

static void resolve_main_class_name(struct java_property_s *prop, char *buf, int buf_size)
{
    char *start = NULL;
    char *first_space = NULL;

    if (buf_size <= sizeof(KW_MAIN_CLASS_NAME)) {
        return;
    }
    start = buf + sizeof(KW_MAIN_CLASS_NAME) - 1;

    (void)snprintf(prop->mainClassName, sizeof(prop->mainClassName), "%s", start);
    first_space = strchr(prop->mainClassName, ' ');
    if (first_space != NULL) {
        *first_space = '\0';
    }
}

// execute `jvm_attach <pid> <nspid> properties`
int get_java_property(int pid, struct java_property_s *prop)
{
    struct jvm_process_info proc_info;
    int nspid;
    char cmd[COMMAND_LEN];
    char output[LINE_BUF_LEN];
    FILE *fp = NULL;
    int ret = -1;

    proc_info.nspid = 0;
    (void)_set_effective_id(pid, &proc_info);
    nspid = proc_info.nspid;

    cmd[0] = 0;
    (void)snprintf(cmd, sizeof(cmd), "%s %d %d properties", ATTACH_BIN_PATH, pid, nspid);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        ERROR("[JAVA_SUPPORT]: failed to execute: %s\n", cmd);
        return ret;
    }

    prop->mainClassName[0] = 0;
    while (fgets(output, sizeof(output), fp) != NULL) {
        if (strncmp(output, KW_MAIN_CLASS_NAME, sizeof(KW_MAIN_CLASS_NAME) - 1) != 0) {
            continue;
        }
        SPLIT_NEWLINE_SYMBOL(output);
        resolve_main_class_name(prop, output, sizeof(output));
        ret = 0;
        break;
    }

    pclose(fp);
    return ret;
}