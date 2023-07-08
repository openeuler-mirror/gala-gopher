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
 * Author: dowzyx
 * Create: 2023-04-07
 * Description: jvm probe prog lifecycle management
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/file.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "common.h"
#include "object.h"
#include "ipc.h"
#include "l7_common.h"
#include "session_conn.h"
#include "java_support.h"

#define JSSE_AGENT_FILE     "JSSEProbeAgent.jar"
#define JSSE_TMP_FILE       "jsse-metrics.txt"
#define JSSE_LOAD_TIMES     3

struct file_conn_hash_t {
    H_HANDLE;
    u32 pid; // key
    int pid_exits;
    struct session_data_args_s args;
};

static struct file_conn_hash_t *file_conn_head = NULL;
static int g_proc_obj_map_fd = -1;

static int l7_load_jsse_agent(struct java_attach_args *args)
{
    int result = 0;
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s obj;
    char comm[TASK_COMM_LEN];

    while (bpf_map_get_next_key(g_proc_obj_map_fd, &key, &next_key) != -1) {
        if (bpf_map_lookup_elem(g_proc_obj_map_fd, &next_key, &obj) != 0) {
            key = next_key;
            continue;
        }
        comm[0] = 0;
        if (detect_proc_is_java(next_key.proc_id, comm, TASK_COMM_LEN) == 0) {
            key = next_key;
            continue;
        }
        // execute java_load only when the proc is a java proc
        int count = 0;
        while (count < JSSE_LOAD_TIMES) {
            if (!java_load(next_key.proc_id, args)) {
                break;
            }
            count++;
        }
        if (count >= JSSE_LOAD_TIMES) {
            ERROR("[L7Probe]: execute java_load to proc: %d failed.\n", next_key.proc_id);
            result = -1;
        }
        key = next_key;
    }

    return result;
}

static int set_session_data_args(struct session_data_args_s *args)
{
    if (args->session_conn_id.tgid == 0) {
        struct file_conn_hash_t *file_conn_hash;
        H_FIND_I(file_conn_head, &args->session_conn_id.tgid, file_conn_hash);
        if (file_conn_hash != NULL) {
            (void)memcpy(args, &file_conn_hash->args, sizeof(struct session_data_args_s));
            args->buf = NULL;
        } else {
            return -1;
        }
    }

    return 0;
}

#define DELIM "|"
#define JSSE_MSG "jsse_msg"
#define SESSION_MSG "Session("
#define JAVA_MSG_START_SEG 0
#define JAVA_MSG_JSSE_SEG 1             // jsse_msg
#define JAVA_MSG_PID_SEG 2              // <pid>
#define JAVA_MSG_SESSIONID_SEG 3        // <session_id>
#define JAVA_MSG_RWTYPE_SEG 6           // Read/Write
#define JAVA_MSG_REMOTE_IP_SEG 7        // <IP>
#define JAVA_MSG_REMOTE_PORT_SEG 8      // <port>

/*
    java msg line may look like this:
        |jsse_msg|662220|Session(1688648699909|TLS_AES_256_GCM_SHA384)|1688648699989|Write|127.0.0.1|58302|This is test message|
    or this:
        |
    or this:
        testmessage second line....
*/
// TODO: 考虑字符串里包含|的情况
static int parse_java_msg_line(char *buffer, struct session_data_args_s *args)
{
    char *token;
    int index = 0;

    for (token = strsep(&buffer, DELIM); token != NULL; token = strsep(&buffer, DELIM)) {
        if (strcmp(token, "\n") == 0) {
            break;
        }

        if (strcmp(token, "") == 0) {
            continue;
        }

        switch (index) {
            case JAVA_MSG_START_SEG:
                if (token[0] != 0) {
                    if (set_session_data_args(args) != 0) {
                        return -1;
                    }
                    args->buf = token;
                    args->bytes_count = strlen(token) + 1;
                    return 0;
                }
                break;
            case JAVA_MSG_JSSE_SEG:
                if (strncmp(token, JSSE_MSG, sizeof(JSSE_MSG) - 1) != 0) {
                    ERROR("[L7Probe]: parse java msg failed. %s\n", token);
                    return -1;
                }
                break;
            case JAVA_MSG_PID_SEG:
                args->session_conn_id.tgid = (int)atoi(token);
                break;
            case JAVA_MSG_SESSIONID_SEG:
                args->session_conn_id.session_id = (s64)atoll(token + sizeof(SESSION_MSG) - 1); 
                break;
            case JAVA_MSG_RWTYPE_SEG:
                if (strncmp(token, "Read", 4) == 0) {
                    args->direct = L7_INGRESS;
                } else if (strncmp(token, "Write", 5) == 0){
                    args->direct = L7_EGRESS;
                } else {
                    args->direct = L7_DIRECT_UNKNOW;
                }
                break;
            case JAVA_MSG_REMOTE_IP_SEG:
                (void)snprintf(args->ip, IP6_LEN, "%s", token);
                break;
            case JAVA_MSG_REMOTE_PORT_SEG:
                args->port = (int)atoi(token);
                args->buf = buffer;
                args->bytes_count = strlen(buffer) + 1;
                return 0;
            default:
                continue;
        }
        index += 1;
    }

    return -1;
}

static void record_last_conn(struct file_ref_s *file_ref, struct session_data_args_s *args)
{
    struct file_conn_hash_t *file_conn;
    H_FIND_I(file_conn_head, &args->session_conn_id.tgid, file_conn);
    if (!file_conn) {
        file_conn = malloc(sizeof(struct file_conn_hash_t));
        if (file_conn == NULL) {
            ERROR("[L7PROBE]: record last conn malloc failed\n");
            return;
        }
    }

    (void)memset(file_conn, 0, sizeof(struct file_conn_hash_t));
    (void)memcpy(&file_conn->args, args, sizeof(struct session_data_args_s));
    file_conn->pid = args->session_conn_id.tgid;
    file_conn->pid_exits = 1;
    file_conn->args.buf = NULL;
    H_ADD_I(file_conn_head, pid, file_conn);
}

static void parse_java_msg(void *ctx, struct file_ref_s *file_ref)
{
    if (ctx == NULL || file_ref == NULL) {
        return;
    }

    struct session_data_args_s data_args = {.is_ssl = 1, .session_conn_id.tgid = file_ref->pid};
    char line[LINE_BUF_LEN];
    line[0] = 0;
    while (fgets(line, LINE_BUF_LEN, file_ref->fp) != NULL) {
        if (parse_java_msg_line(line, &data_args) == 0) {
            submit_sock_data_by_session(ctx, &data_args);
        }
        line[0] = 0;
    }

    record_last_conn(file_ref, &data_args);
    return;
}

static void set_pids_noexit()
{
    struct file_conn_hash_t *item, *tmp;
    if (file_conn_head == NULL) {
        return;
    }
    
    H_ITER(file_conn_head, item, tmp) {
        item->pid_exits = 0;
    }
}

static void clear_pids_noexit()
{
    struct file_conn_hash_t *item, *tmp;
    if (file_conn_head == NULL) {
        return;
    }
    
    H_ITER(file_conn_head, item, tmp) {
        if (item->pid_exits == 0) {
            H_DEL(file_conn_head, item);
            clean_pid_session_hash(item->pid);
        }
    }
}

static void* l7_jsse_msg_handler(void *ctx)
{
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s obj;
    struct java_attach_args args = {0};
    (void)snprintf(args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    while (1) {
        sleep(DEFAULT_PERIOD);
        (void)memset(&key, 0, sizeof(key));
        set_pids_noexit();
        while (bpf_map_get_next_key(g_proc_obj_map_fd, &key, &next_key) != -1) {
            if (bpf_map_lookup_elem(g_proc_obj_map_fd, &next_key, &obj) == 0) {
                java_msg_handler(next_key.proc_id, (void *)&args, parse_java_msg, ctx);
            }
            key = next_key;
        }
        clear_pids_noexit();
    }
    return NULL;
}

int l7_load_probe_jsse(struct l7_mng_s *l7_mng)
{
    int err = 0;
    pthread_t msg_hd_thd;
    struct java_attach_args attach_args = {0};
    (void)strcpy(attach_args.action, "start");
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    g_proc_obj_map_fd = l7_mng->bpf_progs.proc_obj_map_fd;

    // 1. load agent, action: start
    if (!l7_load_jsse_agent(&attach_args)) {
        INFO("[L7PROBE]: jsseagent load(action:start) succeed.\n");
    } else {
        INFO("[L7PROBE]: jsseagent load(action:start) end and some proc load failed.\n");
    }

    // 2. create msg_handler thread
    err = pthread_create(&msg_hd_thd, NULL, l7_jsse_msg_handler, l7_mng);
    if (err != 0) {
        ERROR("L7PROBE]: Failed to create jsse_msg_handler thread.\n");
        return -1;
    }
    l7_mng->java_progs.jss_msg_hd_thd = msg_hd_thd;
    (void)pthread_detach(msg_hd_thd);
    INFO("[L7PROBE]: jsse_msg_handler thread create succeed.\n");

    return 0;
}

void l7_unload_probe_jsse(struct l7_mng_s *l7_mng)
{
    struct java_attach_args attach_args = {0};
    (void)strcpy(attach_args.action, "stop");
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    g_proc_obj_map_fd = l7_mng->bpf_progs.proc_obj_map_fd;

    // 1. load agent, action: stop
    if (!l7_load_jsse_agent(&attach_args)) {
        INFO("[L7PROBE]: jsseagent unload(action:stop) succeed.\n");
    } else {
        INFO("[L7PROBE]: jsseagent unload(action:stop) end and some proc unload failed.\n");
    }

    // 2. kill msg_handler thread
    if (l7_mng->java_progs.jss_msg_hd_thd > 0) {
        if (pthread_cancel(l7_mng->java_progs.jss_msg_hd_thd) != 0) {
            ERROR("[L7PROBE] Fail to kill jsse_msg_handler thread.\n");
        } else {
            INFO("[L7PROBE]: jsse_msg_handler thread kill succeed.\n");
        }
    }

    return;
}