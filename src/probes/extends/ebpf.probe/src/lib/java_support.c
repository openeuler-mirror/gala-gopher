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
#include <time.h>
#include <string.h>
#include <sys/file.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#include "bpf.h"
#include "args.h"
#include "hash.h"
#include "common.h"
#include "java_support.h"

enum java_pid_state_t {
    PID_NOEXIST,
    PID_ELF_TO_ATTACH,
    PID_ELF_NO_NEED_ATTACH // non-java proc or have been attached
};

#define NS_PATH_LEN 128
struct jvm_agent_hash_value {
    enum java_pid_state_t pid_state;
    uid_t eUid;
    gid_t eGid;
    int nspid;
    int attached;
    int ns_changed;
    char ns_java_sym_path[NS_PATH_LEN]; // /tmp/java-sym-<pid>
    char ns_agent_so_path[NS_PATH_LEN]; // /tmp/jvm_agent.so
    char host_proc_dir[PATH_LEN]; // /proc/<pid>/root
    char host_java_sym_file[PATH_LEN]; // /proc/<pid>/root/tmp/java-sym-<pid>/java-symbols.bin
};

struct jvm_agent_hash_t {
    H_HANDLE;
    int pid; // key
    struct jvm_agent_hash_value v; // value
};

static struct jvm_agent_hash_t *jvm_agent_head = NULL;

#define FIND_JAVA_PROC_COMM "ps -e -o pid,comm | grep java | awk '{print $1}'"
#define PROC_COMM "/usr/bin/cat /proc/%u/comm 2> /dev/null"
#define ATTACH_BIN_PATH "/opt/gala-gopher/extend_probes/jvm_attach"
#define ATTACH_CMD "%s %u %u load %s true %s" // jvm_attach <pid> <nspid> load /tmp/jvm_agent.so true /tmp/java-sym-123
#define HOST_SO_DIR "/opt/gala-gopher/extend_probes"
#define AGENT_SO_FILE "jvm_agent.so"
#define HOST_JAVA_SYM_PATH "/proc/%u/root/tmp/java-sym-%u/%s" // /proc/<pid>/root/tmp/java-sym-<pid>/java-symbols.bin
#define NS_TMP_DIR "/tmp"

/*
    [root@localhost ~]# cat /proc/<pid>/status
    Name:   java
    ...
    Uid:    0       <eUid>       0       0
    Gid:    0       <eGid>       0       0
    NStgid: <pid>   <inner_pid>  <inner_inner_pid>
*/
int __set_effective_id(struct jvm_agent_hash_t *pid_bpf_link) {
    uid_t cur_uid = geteuid();
    gid_t cur_gid = getegid();
    uid_t eUid = cur_uid;
    gid_t eGid = cur_gid;
    char path[64];
    int pid = pid_bpf_link->pid;
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

    if (!nspid_found) {
        ret = -1;
    }

    if (pid != nspid) {
        pid_bpf_link->v.ns_changed = 1;
    }


    free(line);
    fclose(status_file);
out:
    pid_bpf_link->v.eGid = eGid;
    pid_bpf_link->v.eUid = eUid;
    pid_bpf_link->v.nspid = nspid;

    return ret;
}

int detect_proc_is_java(int pid, char *comm, int comm_len)
{
    FILE *f = NULL;
    char cmd[LINE_BUF_LEN];
    int is_java = 0;

    if (comm == NULL) {
        WARN("[JAVA_SUPPORT]: comm is null\n", pid);
        return 0;
    }

    cmd[0] = 0;
    (void)snprintf(cmd, LINE_BUF_LEN, PROC_COMM, pid);
    f = popen(cmd, "r");
    if (f == NULL) {
        WARN("[JAVA_SUPPORT]: get proc %u comm fail, popen is null\n", pid);
        return 0;
    }

    comm[0] = 0;
    if (fgets(comm, comm_len, f) == NULL) {
        (void)pclose(f);
        return 0;
    }

    SPLIT_NEWLINE_SYMBOL(comm);
    if (strcmp(comm, "java") == 0) {
        is_java = 1;
    }

    (void)pclose(f);
    return is_java;
}

static int __find_jvm_agent_hash(int pid)
{
    struct jvm_agent_hash_t *item = NULL;

    if (jvm_agent_head == NULL) {
        return -1;
    }

    H_FIND(jvm_agent_head, &pid, sizeof(int), item);
    if (item == NULL) {
        return -1;
    }
    return 0;
}

static int __add_jvm_agent_hash(int pidd)
{
    struct jvm_agent_hash_t *item = malloc(sizeof(struct jvm_agent_hash_t));
    if (item == NULL) {
        ERROR("[JAVA_SUPPORT]: malloc jvm agent hash %u failed\n", pidd);
        return -1;
    }
    (void)memset(item, 0, sizeof(struct jvm_agent_hash_t));

    item->pid = pidd;

    H_ADD(jvm_agent_head, pid, sizeof(int), item);

    return 0;
}

static int __check_proc_to_attach(int proc_obj_map_fd)
{
    FILE *f;
    int pid = 0;
    struct jvm_agent_hash_t *item;
    int ret = 0;
    char line[LINE_BUF_LEN] = {0};
    struct obj_ref_s value = {0};

    f = popen(FIND_JAVA_PROC_COMM, "r");
    if (f == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%d", &pid) != 1) {
            return -1;
        }
        if (proc_obj_map_fd != 0) { // whitelist_enable
            struct proc_s obj = {.proc_id = pid};
            ret = bpf_map_lookup_elem(proc_obj_map_fd, &obj, &value);
            if (ret != 0) {
                continue;
            }
        }

        // 1. check if new proc
        if (__find_jvm_agent_hash(pid) != 0) {
            if (__add_jvm_agent_hash(pid) != 0) {
                ERROR("[JAVA_SUPPORT]: add pid %u failed\n", pid);
                continue;
            }
        }
        // 2. check if the proc need to be attached
        H_FIND(jvm_agent_head, &pid, sizeof(int), item);
        if (item == NULL) {
            continue;
        }

        item->v.pid_state = PID_ELF_NO_NEED_ATTACH;
        if (!item->v.attached) {
            item->v.pid_state = PID_ELF_TO_ATTACH;
            INFO("[JAVA_SUPPORT]: add java pid %u success\n", pid);
        }
        
    }
    return 0;
}

static void __set_pids_inactive()
{
    struct jvm_agent_hash_t *item, *tmp;
    if (jvm_agent_head == NULL) {
        return;
    }
    
    H_ITER(jvm_agent_head, item, tmp) {
        item->v.pid_state = PID_NOEXIST;
    }
}

static int __mkdir(char dst_dir[])
{
    int ret = 0;
    if (access(dst_dir, F_OK) != 0) {
        FILE *fp;
        char command[COMMAND_LEN] = {0};
        (void)snprintf(command, COMMAND_LEN, "/usr/bin/mkdir -p %s", dst_dir);
        fp = popen(command, "r");
        if (fp == NULL) {
            ret = -1;
        }
        (void)pclose(fp);
    }
    
    return ret;
}

int get_host_java_sym_file(int pid, char *file_path, int path_len)
{
    if (file_path == NULL || path_len <= 0) {
        return -1;
    }

    // TODO: add start_time_ticks?
    (void)snprintf(file_path, path_len, HOST_JAVA_SYM_PATH, pid, pid, JAVA_SYM_FILE);
    if (access(file_path, F_OK) != 0) {
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
static int __set_attach_argv(struct jvm_agent_hash_t *pid_bpf_link)
{
    int ret = 0;
    int pid = pid_bpf_link->pid;
    
    char *host_proc_dir = pid_bpf_link->v.host_proc_dir;
    (void)snprintf(host_proc_dir, PATH_LEN, "/proc/%u/root", pid);
    ret = __mkdir(host_proc_dir);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: proc %u mkdir fail when copy agent so\n", pid);
        return ret;
    }

    char *ns_agent_so_path = pid_bpf_link->v.ns_agent_so_path;
    (void)snprintf(ns_agent_so_path, NS_PATH_LEN, "%s/%s", NS_TMP_DIR, AGENT_SO_FILE);
    char host_agent_so_path[LINE_BUF_LEN];
    (void)snprintf(host_agent_so_path, LINE_BUF_LEN, "%s%s", pid_bpf_link->v.host_proc_dir, ns_agent_so_path);

    if (access(host_agent_so_path, 0) != 0) {
        char src_agent_so[PATH_LEN] = {0};
        (void)snprintf(src_agent_so, PATH_LEN, "%s/%s", HOST_SO_DIR, AGENT_SO_FILE);
        ret = copy_file(host_agent_so_path, src_agent_so); // overwrite is ok.
        if (ret != 0) {
            ERROR("[JAVA_SUPPORT]: proc %u copy %s from %s file fail \n", pid, host_agent_so_path, src_agent_so);
            return ret;
        }
    }

    ret = chown(host_agent_so_path, pid_bpf_link->v.eUid, pid_bpf_link->v.eGid);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: chown %s to %u %u fail when set ns_agent_so_path\n", host_agent_so_path, pid_bpf_link->v.eUid, pid_bpf_link->v.eGid);
        return ret;
    }

    (void)snprintf(pid_bpf_link->v.ns_java_sym_path, NS_PATH_LEN, "/tmp/java-sym-%u", pid_bpf_link->pid); // TODO: add start_time_ticks?

    char host_java_sym_dir[LINE_BUF_LEN] = {0};
    (void)snprintf(host_java_sym_dir, LINE_BUF_LEN, "%s%s", pid_bpf_link->v.host_proc_dir, pid_bpf_link->v.ns_java_sym_path);
    ret = __mkdir(host_java_sym_dir);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: proc %u mkdir fail when set host_java_sym_dir\n", pid_bpf_link->pid);
        return ret;
    }
    ret = chown(host_java_sym_dir, pid_bpf_link->v.eUid, pid_bpf_link->v.eGid);
    if (ret != 0) {
        ERROR("[JAVA_SUPPORT]: proc %u chown fail when set ns_java_sym_path\n", pid_bpf_link->pid);
        return ret;
    }

    get_host_java_sym_file(pid, pid_bpf_link->v.host_java_sym_file, PATH_LEN);
    return ret;
}

static void __clear_invalid_pids()
{
    struct jvm_agent_hash_t *pid_bpf_links, *tmp;
    if (jvm_agent_head == NULL) {
        return;
    }
    H_ITER(jvm_agent_head, pid_bpf_links, tmp) {
        if (pid_bpf_links->v.pid_state == PID_NOEXIST) {
            INFO("[JAVA_SUPPORT]: clear bpf link of pid %u\n", pid_bpf_links->pid);
            H_DEL(jvm_agent_head, pid_bpf_links);
            (void)free(pid_bpf_links);
        }
    }
}
/*
   In container scenario, it's necessary to set to the namespace of the container
   when attaching. Yet a multi-threaded process may not change user namespace with setns().
   Therefore, we have to do attach in the child process (because the stackprobe process is multi-threaded).
*/
static void __do_attach(struct jvm_agent_hash_t *pid_bpf_link) {
    char cmd[LINE_BUF_LEN] = {0};
    char result_buf[LINE_BUF_LEN];
    (void)snprintf(cmd, LINE_BUF_LEN,
        ATTACH_CMD,
        ATTACH_BIN_PATH,
        pid_bpf_link->pid,
        pid_bpf_link->v.nspid,
        pid_bpf_link->v.ns_agent_so_path,
        pid_bpf_link->v.ns_java_sym_path);

    FILE *f = popen(cmd, "r");
    if (f == NULL) {
        ERROR("[JAVA_SUPPORT]: attach fail, popen error.\n");
    }
    INFO("[JAVA_SUPPORT]: __do_attach %s\n", cmd);
    while(fgets(result_buf, sizeof(result_buf), f) != NULL) {
        printf("%s", result_buf);
    }
    (void)pclose(f);
    return;
}

void *java_support(void *arg)
{
    int err = 0;
    struct jvm_agent_hash_t *pid_bpf_link, *tmp;
    int proc_obj_map_fd = *(int *)arg;

    while (1) {
        sleep(DEFAULT_PERIOD);
        __set_pids_inactive();
        if (__check_proc_to_attach(proc_obj_map_fd) != 0) {
            continue;
        }

        H_ITER(jvm_agent_head, pid_bpf_link, tmp) { // for pids
            // only when the proc is a java proc and has not been successfully attached
            if (pid_bpf_link->v.pid_state == PID_ELF_TO_ATTACH) {
                pid_bpf_link->v.attached = 1; // TODO: Is it necessary to try to attach again?
                (void)__set_effective_id(pid_bpf_link);
                err = __set_attach_argv(pid_bpf_link);
                if (err != 0) {
                    continue;
                }
                __do_attach(pid_bpf_link);
            }
        }
        __clear_invalid_pids();
    }

    return NULL;
}
