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
#include <sys/prctl.h>

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
};

static struct file_conn_hash_t *file_conn_head = NULL;
static int g_proc_obj_map_fd = -1;

static int add_java_proc(struct l7_mng_s *l7_mng, int proc_id)
{
    struct java_proc_s *new_item = (struct java_proc_s *)malloc(sizeof(struct java_proc_s));
    if (!new_item) {
        return -1;
    }
    new_item->proc_id = proc_id;
    H_ADD_I(l7_mng->java_procs, proc_id, new_item);

    return 0;
}

static void clear_java_proc(struct l7_mng_s *l7_mng)
{
    struct java_proc_s *item, *tmp;
    if (H_COUNT(l7_mng->java_procs) > 0) {
        H_ITER(l7_mng->java_procs, item, tmp) {
            H_DEL(l7_mng->java_procs, item);
            free(item);
        }
    }
}

// /opt/gala-gopher/lib/jvm_attach <pid> <pid> load instrument false "/tmp/JSSEProbeAgent.jar=<pid>,/tmp/java-data-<pid>,start"
static int l7_load_jsse_agent(struct l7_mng_s *l7_mng, struct java_attach_args *args)
{
    int result = 0;
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s obj;
    char comm[TASK_COMM_LEN];

    while (bpf_map_get_next_key(g_proc_obj_map_fd, &key, &next_key) == 0) {
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
        add_java_proc(l7_mng, next_key.proc_id);
        key = next_key;
    }

    return result;
}

#define DELIM "|"
#define JSSE_MSG "jsse_msg"
#define SESSION_MSG "Session("
#define JAVA_MSG_JSSE_SEG 2             // jsse_msg
#define JAVA_MSG_PID_SEG 3              // <pid>
#define JAVA_MSG_SESSIONID_SEG 4        // <session_id>
#define JAVA_MSG_RWTYPE_SEG 7           // Read/Write
#define JAVA_MSG_ROLE_SEG 8             // s/c, which means server or client
#define JAVA_MSG_REMOTE_IP_SEG 9        // <IP>
#define JAVA_MSG_REMOTE_PORT_SEG 10     // <port>

/*
    java msg line may look like this:
        |jsse_msg|662220|Session(1688648699909|TLS_AES_256_GCM_SHA384)|1688648699989|Write|s|127.0.0.1|58302|This is test message|
    or this:
        |
    or this:
        testmessage second line....
*/
// TODO: 考虑字符串里包含|的情况
static int parse_java_msg_line(char *buf, struct session_data_args_s *args)
{
    int ret;
    char *token;
    int index = 0;
    char *buffer = buf;
    // buf is origin line. token is before DELIM. buffer is after DELIM.
    for (token = strsep(&buffer, DELIM); token != NULL; token = strsep(&buffer, DELIM)) {
        index += 1;
        if (strcmp(token, "\n") == 0) {
            break;
        }

        if (strcmp(token, "") == 0) {
            continue;
        }

        switch (index) {
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
            case JAVA_MSG_ROLE_SEG:
                if (token[0] == 's') {
                    args->role = L4_SERVER;
                } else if (token[0] == 'c'){
                    args->role = L4_CLIENT;
                } else {
                    args->role = L4_UNKNOW;
                }
                break;
            case JAVA_MSG_REMOTE_IP_SEG:
                (void)snprintf(args->ip, IP6_LEN, "%s", token);
                break;
            case JAVA_MSG_REMOTE_PORT_SEG:
                args->port = (int)atoi(token);
                ret = snprintf(args->buf, CONN_DATA_MAX_SIZE, "%s", buffer);
                if (ret < 1 || ret >= CONN_DATA_MAX_SIZE) {
                    return -1;
                }
                args->bytes_count = ret;
                return ret;
            default:
                continue;
        }
    }

    return -1;
}

static void record_last_conn(struct file_ref_s *file_ref, struct session_data_args_s *args)
{
    struct file_conn_hash_t *file_conn;

    if (args == NULL) {
        return;
    }

    H_FIND_I(file_conn_head, &args->session_conn_id.tgid, file_conn);
    if (!file_conn) {
        file_conn = malloc(sizeof(struct file_conn_hash_t));
        if (file_conn == NULL) {
            ERROR("[L7PROBE]: record last conn malloc failed\n");
            return;
        }
		(void)memset(file_conn, 0, sizeof(struct file_conn_hash_t));
        H_ADD_I(file_conn_head, pid, file_conn);
    }

    file_conn->pid = args->session_conn_id.tgid;
    file_conn->pid_exits = 1;
}

static void parse_java_msg(void *ctx, struct file_ref_s *file_ref)
{
    int ret, remain_len;
    if (ctx == NULL || file_ref == NULL) {
        return;
    }

    struct session_data_args_s data_args = {.is_ssl = 1, .session_conn_id.tgid = file_ref->pid};
    char line[LINE_BUF_LEN];
    line[0] = 0;
    char *pos;
    while (fgets(line, LINE_BUF_LEN, file_ref->fp) != NULL) {
        DEBUG("[L7PROBE]: to parse java msg: %c,%s", line[0],line);
        if (line[0] == '|') { // this is the beginning or end of the message
            submit_sock_data_by_session(ctx, &data_args);
            remain_len = CONN_DATA_MAX_SIZE;
            pos = data_args.buf;
            if (strlen(line) > 5 && line[1] == 'j' && line[2] == 's' && line[3] == 's' && line[4] == 'e') { // beginning
                ret = parse_java_msg_line(line, &data_args);
                if (ret < 1) {
                    ERROR("[L7PROBE]: parse java msg failed: %s", line);
                    continue;
                }
                remain_len -= ret;
                pos += ret;
            } else {
                continue;
            }
        } else if (line[0] == 0) {
            continue;
        } else {
            ret = __snprintf(&pos, remain_len, &remain_len, "%s", line);
            if (ret < 0) {
                ERROR("[L7PROBE]: append java msg failed: %s", line);
                continue;
            }
            data_args.bytes_count = CONN_DATA_MAX_SIZE - remain_len;
        }
        line[0] = 0;
    }
    submit_sock_data_by_session(ctx, &data_args);
    record_last_conn(file_ref, &data_args);
    return;
}

static void set_pids_noexit(void)
{
    struct file_conn_hash_t *item, *tmp;
    if (file_conn_head == NULL) {
        return;
    }
    
    H_ITER(file_conn_head, item, tmp) {
        item->pid_exits = 0;
    }
}

static void clear_pids_noexit(void)
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
    struct java_attach_args args = {0};
    (void)snprintf(args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);
    prctl(PR_SET_NAME, "[JSSEMSG]");

    struct l7_mng_s *l7_mng = (struct l7_mng_s *)ctx;
    if (l7_mng == NULL) {
        ERROR("[L7PROBE]: l7_mng is NULL.\n");
        return NULL;
    }

    while (1) {
        sleep(1);
        set_pids_noexit();
        struct java_proc_s *item, *tmp;
        if (H_COUNT(l7_mng->java_procs) > 0) {
            H_ITER(l7_mng->java_procs, item, tmp) {
                java_msg_handler(item->proc_id, (void *)&args, parse_java_msg, ctx);
            }
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
    if (!l7_load_jsse_agent(l7_mng, &attach_args)) {
        DEBUG("[L7PROBE]: jsseagent load(action:start) succeed.\n");
    } else {
        DEBUG("[L7PROBE]: jsseagent load(action:start) end and some proc load failed.\n");
    }

    // 2. create msg_handler thread
    err = pthread_create(&msg_hd_thd, NULL, l7_jsse_msg_handler, l7_mng);
    if (err != 0) {
        ERROR("L7PROBE]: Failed to create jsse_msg_handler thread.\n");
        return -1;
    }
    l7_mng->java_progs.jss_msg_hd_thd = msg_hd_thd;
    (void)pthread_detach(msg_hd_thd);
    DEBUG("[L7PROBE]: jsse_msg_handler thread create succeed.\n");

    return 0;
}

void l7_unload_probe_jsse(struct l7_mng_s *l7_mng)
{
    struct java_attach_args attach_args = {0};
    (void)strcpy(attach_args.action, "stop");
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, JSSE_AGENT_FILE);
    (void)snprintf(attach_args.tmp_file_name, FILENAME_LEN, JSSE_TMP_FILE);

    g_proc_obj_map_fd = l7_mng->bpf_progs.proc_obj_map_fd;

    clear_java_proc(l7_mng);

    // 1. load agent, action: stop
    if (!l7_load_jsse_agent(l7_mng, &attach_args)) {
        DEBUG("[L7PROBE]: jsseagent unload(action:stop) succeed.\n");
    } else {
        DEBUG("[L7PROBE]: jsseagent unload(action:stop) end and some proc unload failed.\n");
    }

    // 2. kill msg_handler thread
    if (l7_mng->java_progs.jss_msg_hd_thd > 0) {
        if (pthread_cancel(l7_mng->java_progs.jss_msg_hd_thd) != 0) {
            ERROR("[L7PROBE] Fail to kill jsse_msg_handler thread.\n");
        } else {
            DEBUG("[L7PROBE]: jsse_msg_handler thread kill succeed.\n");
        }
    }

    return;
}