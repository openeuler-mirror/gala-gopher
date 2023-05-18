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
 * Author: luzhihao
 * Create: 2023-04-06
 * Description: probe managment
 ******************************************************************************/
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <dlfcn.h>
#include <cjson/cJSON.h>
#include <sys/epoll.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ipc.h"
#include "probe_mng.h"
#include "pod_mng.h"
#include "snooper.h"
#include "probe_params_parser.h"

struct probe_define_s probe_define[] = {
    {"baseinfo",            PROBE_BASEINFO},
    {"virt",                PROBE_VIRT},
    {"flamegraph",          PROBE_FG},
    {"l7",                  PROBE_L7},
    {"tcp",                 PROBE_TCP},
    {"socket",              PROBE_SOCKET},
    {"io",                  PROBE_IO},
    {"proc",                PROBE_PROC},
    {"jvm",                 PROBE_JVM},
    {"redis_sli",           PROBE_REDIS_SLI},
    {"postgre_sli",         PROBE_POSTGRE_SLI},
    {"opengauss_sli",       PROBE_GAUSS_SLI},
    {"dnsmasq",             PROBE_DNSMASQ},
    {"lvs",                 PROBE_LVS},
    {"nginx",               PROBE_NGINX},
    {"haproxy",             PROBE_HAPROXY},
    {"kafka",               PROBE_KAFKA}
};

static struct probe_mng_s *g_probe_mng;

void get_probemng_lock(void)
{
    (void)pthread_rwlock_wrlock(&g_probe_mng->rwlock);
}

void put_probemng_lock(void)
{
    (void)pthread_rwlock_unlock(&g_probe_mng->rwlock);
}

u32 get_probe_status_flags(struct probe_s* probe)
{
    u32 probe_status_flags;
    (void)pthread_rwlock_wrlock(&probe->rwlock);
    probe_status_flags = probe->probe_status.status_flags;
    (void)pthread_rwlock_unlock(&probe->rwlock);

    return probe_status_flags;
}

void set_probe_status_flags(struct probe_s* probe, u32 flags)
{
    (void)pthread_rwlock_wrlock(&probe->rwlock);
    probe->probe_status.status_flags |= flags;
    (void)pthread_rwlock_unlock(&probe->rwlock);
}

void unset_probe_status_flags(struct probe_s* probe, u32 flags)
{
    (void)pthread_rwlock_wrlock(&probe->rwlock);
    probe->probe_status.status_flags &= ~(flags);
    (void)pthread_rwlock_unlock(&probe->rwlock);
}

static int attach_probe_fd(struct probe_mng_s *probe_mng, struct probe_s *probe)
{
    int ret;
    struct epoll_event event;

    if (probe_mng->ingress_epoll_fd < 0) {
        return -1;
    }

    event.events = EPOLLIN;
    event.data.ptr = probe->fifo;

    ret = epoll_ctl(probe_mng->ingress_epoll_fd, EPOLL_CTL_ADD, probe->fifo->triggerFd, &event);
    if (ret) {
        ERROR("[PROBMNG] add EPOLLIN event failed, probe %s.\n", probe->name);
        return ret;
    }
    return 0;
}

static void detach_probe_fd(struct probe_mng_s *probe_mng, struct probe_s *probe)
{
    struct epoll_event event;
    if (probe_mng->ingress_epoll_fd < 0) {
        return;
    }

    event.events = EPOLLIN;
    event.data.ptr = probe->fifo;

    (void)epoll_ctl(probe_mng->ingress_epoll_fd, EPOLL_CTL_DEL, probe->fifo->triggerFd, &event);
    return;
}

static void destroy_probe(struct probe_s *probe)
{
    int i;

    if (probe == NULL) {
        return;
    }

    if (probe->name) {
        free(probe->name);
        probe->name = NULL;
    }

    if (probe->bin) {
        free(probe->bin);
        probe->bin = NULL;
    }

    if (probe->chk_cmd) {
        free(probe->chk_cmd);
        probe->chk_cmd = NULL;
    }

    if (probe->fifo != NULL) {
        FifoDestroy(probe->fifo);
        probe->fifo = NULL;
    }

    for (i = 0 ; i < probe->snooper_conf_num ; i++) {
        free_snooper_conf(probe->snooper_confs[i]);
        probe->snooper_confs[i] = NULL;
    }

    for (i = 0; i < SNOOPER_MAX; i++) {
        free_snooper_obj(probe->snooper_objs[i]);
        probe->snooper_objs[i] = NULL;
    }

    probe->snooper_conf_num = 0;
    (void)pthread_rwlock_destroy(&probe->rwlock);

    detach_probe_fd(g_probe_mng, probe);
    free(probe);
    probe = NULL;
}

static struct probe_s* new_probe(const char* name, enum probe_type_e probe_type)
{
    int ret;
    struct probe_s *probe = NULL;

    probe = (struct probe_s *)malloc(sizeof(struct probe_s));
    if (probe == NULL) {
        return NULL;
    }

    memset(probe, 0, sizeof(struct probe_s));
    probe->name = strdup(name);

    ret = pthread_rwlock_init(&probe->rwlock, NULL);
    if (ret) {
        goto err;
    }

    probe->fifo = FifoCreate(MAX_FIFO_SIZE);
    if (probe->fifo == NULL) {
        goto err;
    }
    probe->probe_type = probe_type;
    set_default_params(probe);

    ret = attach_probe_fd(g_probe_mng, probe);
    if (ret) {
        goto err;
    }

    probe->pid = -1;

    return probe;

err:
    destroy_probe(probe);
    return NULL;
}

static int is_extend_probe(struct probe_s *probe)
{
    if (probe->bin == NULL) {
        return 0;
    }

    // Independent running binary for extend probe, Otherwise, it's a native probe
    if (access(probe->bin, 0) == 0) {
        return 1;
    }

    if (strchr(probe->bin, '/') != NULL) {
        return 1;
    }

    return 0;
}

static int set_probe_entry(struct probe_s *probe)
{
    int ret = 0;
    char entry_str[MAX_PROBE_NAME_LEN];

    if (probe->probe_entry != NULL) {
        return 0;
    }

    void *hdl = dlopen(NULL, RTLD_NOW | RTLD_GLOBAL);
    if (hdl == NULL) {
        return -1;
    }

    entry_str[0] = 0;
    (void)snprintf(entry_str, MAX_PROBE_NAME_LEN - 1, "probe_main_%s", probe->bin);
    probe->probe_entry = dlsym(hdl, (char *)entry_str);
    if (probe->probe_entry == NULL) {
        ERROR("[PROBEMNG] Fail to set entry for probe(name: %s) ,unknown func: %s\n", probe->name, entry_str);
        ret = -1;
        goto end;
    }
end:
    dlclose(hdl);
    return ret;
}

#define INSTALL_DIR_CMD "/usr/bin/rpm -ql gala-gopher | grep -v conf | grep %s | head -n1 2>/dev/null"
static int __get_install_dir(const char *bin_name, char install_dir[], size_t size)
{
    char cmd[COMMAND_LEN];

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, INSTALL_DIR_CMD, bin_name);
    if (exec_cmd((const char *)cmd, install_dir, size) < 0) {
        return -1;
    }

    return 0;
}

static int set_probe_bin(struct probe_s *probe, const char *bin)
{
    char install_dir[PATH_LEN];
    char bin_name[PATH_LEN];

    if (probe->bin) {
        free(probe->bin);
        probe->bin = NULL;
    }

    if (strlen(bin) && bin[0] == '$') {
        bin_name[0] = 0;
        install_dir[0] = 0;

        char *p = strrchr(bin, '/');
        if (p && strlen(p) > 1) {
            (void)snprintf(bin_name, PATH_LEN, "%s", p + 1);
            int ret = __get_install_dir((const char *)bin_name, install_dir, PATH_LEN);
            if (!ret) {
                probe->bin = strdup(install_dir);
            }
        } else {
            return -1;
        }
    } else {
        probe->bin = strdup(bin);
    }

    if (is_extend_probe(probe)) {
        probe->is_extend_probe = 1;
    } else {
        int ret = set_probe_entry(probe);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

static void set_probe_chk_cmd(struct probe_s *probe, const char *chk_cmd)
{
    if (probe->chk_cmd) {
        free(probe->chk_cmd);
        probe->chk_cmd = NULL;
    }

    probe->chk_cmd = strdup(chk_cmd);
}

static int get_probe_pid(struct probe_s *probe)
{
    int pid;
    (void)pthread_rwlock_wrlock(&probe->rwlock);
    pid = probe->pid;
    (void)pthread_rwlock_unlock(&probe->rwlock);
    return pid;
}

static void set_probe_pid(struct probe_s *probe, int pid)
{
    (void)pthread_rwlock_wrlock(&probe->rwlock);
    probe->pid = pid;
    (void)pthread_rwlock_unlock(&probe->rwlock);
}

static int check_probe_need_start(const char *check_cmd)
{
    /* ret val: 1 need start / 0 no need start */
    if (!check_cmd || !strlen(check_cmd)) {
        return 1;
    }

    int cnt = 0;
    FILE *fp = NULL;
    char data[COMMAND_LEN];

    fp = popen(check_cmd, "r");
    if (fp == NULL) {
        ERROR("popen error!(cmd = %s)\n", check_cmd);
        return 0;
    }

    data[0] = 0;
    if (fgets(data, sizeof(data), fp) != NULL) {
        cnt = atoi(data);
    }
    pclose(fp);

    return (cnt > 0);
}

static char is_probe_ready(struct probe_s *probe)
{
    if (!probe->cb) {
        goto end;
    }

    if (IS_NATIVE_PROBE(probe)) {
        if (probe->probe_entry == NULL) {
            goto end;
        }
    } else {
        if (probe->bin == NULL || access(probe->bin, 0) != 0) {
            goto end;
        }

        if (probe->fifo == NULL) {
            goto end;
        }

        if (check_probe_need_start(probe->chk_cmd) != 1) {
            goto end;
        }
    }

    return 1;
end:
    ERROR("[PROBEMNG] Probe is not ready(name: %s)\n", probe->name);
    return 0;
}

static int try_start_probe(struct probe_s *probe)
{
    int ret;

    if (IS_RUNNING_PROBE(probe)) {
        return 0;
    }

    if (!IS_STARTED_PROBE(probe)) {
        return 0;
    }

    if (!is_probe_ready(probe)) {
        return -1;
    }

    ret = pthread_create(&probe->tid, NULL, probe->cb, probe);
    if (ret != 0) {
        ERROR("[PROBEMNG] Failed to create thread for probe(name: %s errno: %d).\n",
            probe->name, errno);
        return -1;
    }

    (void)pthread_detach(probe->tid);
    return 0;
}

static int start_probe(struct probe_s *probe)
{
    if (IS_RUNNING_PROBE(probe)) {
        return 0;
    }

    SET_PROBE_FLAGS(probe, PROBE_FLAGS_STARTED);
    UNSET_PROBE_FLAGS(probe, PROBE_FLAGS_STOPPING);

    return try_start_probe(probe);
}

static int delete_probe(struct probe_s *probe)
{
    if (!IS_STOPPED_PROBE(probe)) {
        ERROR("[PROBEMNG] Fail to delete probe(name:%s) which has not been stopped\n", probe->name);
        return -1;
    }

    UNSET_PROBE_FLAGS(probe, PROBE_FLAGS_STARTED);

    g_probe_mng->probes[probe->probe_type] = NULL;
    destroy_probe(probe);
    return 0;
}

static int stop_probe(struct probe_s *probe)
{
    int pid;
    if (!IS_RUNNING_PROBE(probe)) {
        ERROR("[PROBEMNG] Fail to stop probe(name:%s) which is not running\n", probe->name);
        return -1;
    }

    SET_PROBE_FLAGS(probe, PROBE_FLAGS_STOPPING);
    UNSET_PROBE_FLAGS(probe, PROBE_FLAGS_STARTED);

    if (IS_NATIVE_PROBE(probe)) {
        kill(probe->tid, SIGINT);
    } else {
        pid = get_probe_pid(probe);
        if (pid < 0) {
            ERROR("[PROBEMNG] Fail to find process of extend probe(name:%s)\n", probe->name);
            return -1;
        }
        kill(pid, SIGINT);
    }

    set_probe_pid(probe, -1);
    return 0;
}

static enum probe_type_e get_probe_type_by_name(const char *probe_name)
{
    size_t size = sizeof(probe_define) / sizeof(struct probe_define_s);

    if (probe_name == NULL) {
        return PROBE_TYPE_MAX;
    }

    for (int i = 0; i < size; i++) {
        if (!strcasecmp(probe_define[i].desc, probe_name)) {
            return probe_define[i].type;
        }
    }

    return PROBE_TYPE_MAX;
}

static struct probe_s *get_probe_by_name(const char *probe_name)
{
    enum probe_type_e probe_type = get_probe_type_by_name(probe_name);
    if (probe_type >= PROBE_TYPE_MAX) {
        return NULL;
    }

    if (g_probe_mng->probes[probe_type]) {
        return g_probe_mng->probes[probe_type];
    }

    g_probe_mng->probes[probe_type] = new_probe(probe_name, probe_type);
    return g_probe_mng->probes[probe_type];
}

static void probe_printer_cmd(struct probe_s *probe, cJSON *json)
{
    cJSON_AddStringToObject(json, "bin", probe->bin ? :"");
    cJSON_AddStringToObject(json, "check_cmd", probe->chk_cmd ? :"");
}

static int probe_parser_cmd(struct probe_s *probe, const cJSON *item)
{
    int ret;
    cJSON *bin_object, *chkcmd_object;
#if 0
    int is_extend_probe_bak = probe->is_extend_probe;
    char *bin_bak = NULL;
    char *chk_cmd_bak = NULL;
    ProbeMain probe_entry_bak = probe->probe_entry;
    bin_bak = probe->bin ? strdup(probe->bin) : NULL;
    chk_cmd_bak = probe->chk_cmd ? strdup(probe->chk_cmd) : NULL;
#endif

    if (IS_RUNNING_PROBE(probe)) {
        ERROR("[PROBEMNG] Fail to modify cmd of probe(name:%s) which is running\n", probe->name);
        return -1;
    }

    bin_object = cJSON_GetObjectItem(item, "bin");
    if (bin_object == NULL || bin_object->type != cJSON_String) {
        return -1;
    }

    if (set_probe_bin(probe, (const char *)bin_object->valuestring)) {
        return -1;
    }

    chkcmd_object = cJSON_GetObjectItem(item, "check_cmd");
    if ((chkcmd_object != NULL) && (chkcmd_object->type == cJSON_String)) {
        set_probe_chk_cmd(probe, (const char *)chkcmd_object->valuestring);
    }

    if (IS_EXTEND_PROBE(probe)) {
        probe->cb = extend_probe_thread_cb;
    } else {
        probe->cb = native_probe_thread_cb;
    }

    return 0;

#if 0
resume:
    if (probe->bin) {
        free(probe->bin);
    }
    if (probe->chk_cmd) {
        free(probe->chk_cmd);
    }
    probe->bin = chk_cmd_bak;
    probe->bin = bin_bak;
    probe->is_extend_probe = is_extend_probe_bak;
    probe->probe_entry = probe_entry_bak;
    return -1;
#endif
}

static int probe_parser_operate(struct probe_s *probe, const cJSON *item)
{
    if (item->type != cJSON_String) {
        ERROR("[PROBEMNG] Operation must be string, probe(name:%s)\n", probe->name);
        return -1;
    }

    if (!strcasecmp("start", (const char *)item->valuestring)) {
        return start_probe(probe);
    }

    if (!strcasecmp("stop", (const char *)item->valuestring)) {
        return stop_probe(probe);
    }

    if (!strcasecmp("delete", (const char *)item->valuestring)) {
        return delete_probe(probe);
    }

    ERROR("[PROBEMNG] Unsupported operation %s to probe(name:%s)\n", (const char *)item->valuestring, probe->name);
    return -1;
}

static void probe_printer_probes(struct probe_s *probe, cJSON *json)
{
    return print_snooper(probe, json);
}

static int probe_parser_probes(struct probe_s *probe, const cJSON *item)
{
    return parse_snooper(probe, item);
}

static int probe_parser_params(struct probe_s *probe, const cJSON *item)
{
    if (parse_params(probe, item)) {
        return -1;
    }

    if (IS_RUNNING_PROBE(probe) && IS_EXTEND_PROBE(probe)) {
        //TODO: send params to probe by ipc msg
    }
    return 0;
}

typedef int (*probe_json_parser)(struct probe_s *, const cJSON *);
typedef void (*probe_json_printer)(struct probe_s *, cJSON *);
struct probe_parser_s {
    const char *item;
    probe_json_parser parser;
    probe_json_printer printer;
};

// !!!NOTICE:The function sequence cannot be changed.
struct probe_parser_s probe_parsers[] = {
    {"cmd",     probe_parser_cmd,     probe_printer_cmd},
    {"probes",  probe_parser_probes,  probe_printer_probes},
    {"params",  probe_parser_params,  NULL},
    {"operate", probe_parser_operate, NULL}
};

int parse_probe_json(const char *probe_name, const char *probe_content)
{
    int ret = -1;
    struct probe_parser_s *parser;
    cJSON *json = NULL, *item;

    get_probemng_lock();

    struct probe_s *probe = get_probe_by_name(probe_name);
    if (probe == NULL) {
        goto end;
    }
    json = cJSON_Parse(probe_content);
    if (json == NULL) {
        goto end;
    }

    size_t size = sizeof(probe_parsers) / sizeof(struct probe_parser_s);
    for (int i = 0; i < size; i++) {
        parser = &(probe_parsers[i]);
        item = cJSON_GetObjectItem(json, parser->item);
        if (item == NULL) {
            continue;
        }

        ret = parser->parser(probe, item);
        if (ret) {
            break;
        }
    }

end:
    put_probemng_lock();
    if (json) {
        cJSON_Delete(json);
    }
    return ret;
}

char *get_probe_json(const char *probe_name)
{
    cJSON *res = NULL, *item;
    char *buf = NULL;
    struct probe_s *probe;
    struct probe_parser_s *parser;

    get_probemng_lock();

    enum probe_type_e probe_type = get_probe_type_by_name(probe_name);
    if (probe_type >= PROBE_TYPE_MAX) {
        goto end;
    }

    res = cJSON_CreateObject();
    probe = g_probe_mng->probes[probe_type];
    if (probe == NULL) {
        goto end;
    }

    size_t size = sizeof(probe_parsers) / sizeof(struct probe_parser_s);
    for (int i = 0; i < size; i++) {
        parser = &(probe_parsers[i]);
        if (parser->printer) {
            item = cJSON_CreateObject();
            parser->printer(probe, item);
            cJSON_AddItemToObject(res, parser->item, item);
        }
    }

end:
    if (res) {
        buf = cJSON_PrintUnformatted(res);
        cJSON_Delete(res);
    }
    put_probemng_lock();
    return buf;
}

void destroy_probe_mng(void)
{
    struct probe_s *probe;

    if (g_probe_mng == NULL) {
        return;
    }

    if (g_probe_mng->msq_id > 0) {
        destroy_ipc_msg_queue(g_probe_mng->msq_id);
        g_probe_mng->msq_id = -1;
    }

    (void)pthread_rwlock_destroy(&g_probe_mng->rwlock);

    for (int i = 0; i < PROBE_TYPE_MAX; i++) {
        destroy_probe(g_probe_mng->probes[i]);
        g_probe_mng->probes[i] = NULL;
    }

    unload_snooper_bpf(g_probe_mng);
    free(g_probe_mng);
    g_probe_mng = NULL;
    del_pods();
}

struct probe_mng_s *create_probe_mng(void)
{
    int msq_id;

    if (g_probe_mng != NULL) {
        return g_probe_mng;
    }

    g_probe_mng = (struct probe_mng_s *)malloc(sizeof(struct probe_mng_s));
    if (g_probe_mng == NULL) {
        return NULL;
    }

    memset(g_probe_mng, 0, sizeof(struct probe_mng_s));
    g_probe_mng->ingress_epoll_fd = -1;
    g_probe_mng->msq_id = -1;

    int ret = pthread_rwlock_init(&g_probe_mng->rwlock, NULL);
    if (ret) {
        goto err;
    }

    ret = load_snooper_bpf(g_probe_mng);
    if (ret) {
        goto err;
    }

    msq_id = create_ipc_msg_queue(IPC_CREAT | IPC_EXCL);
    if (msq_id < 0) {
        goto err;
    }
    g_probe_mng->msq_id = msq_id;

    g_probe_mng->keeplive_ts = (time_t)time(NULL);

    return g_probe_mng;

err:
    destroy_probe_mng();
    return NULL;
}

static char is_valid_pid(int pid)
{
    const char *fmt = "/proc/%d/comm";
    char proc_comm[PATH_LEN];

    proc_comm[0] = 0;
    (void)snprintf(proc_comm, PATH_LEN, fmt, pid);
    if (access(proc_comm, 0) != 0) {
        return 0;
    }
    return 1;
}

static void keeplive_probes(struct probe_mng_s *probe_mng)
{
    int pid;
    struct probe_s *probe;

    for (int i = 0; i < PROBE_TYPE_MAX; i++) {
        probe = probe_mng->probes[i];
        if (probe == NULL) {
            continue;
        }

        pid = get_probe_pid(probe);
        if (pid < 0) {
            continue;
        }
        if (is_valid_pid(pid)) {
            continue;
        }

        (void)try_start_probe(probe);
        break;

    }
}

#define __PROBE_KEEPLIVE_TIMEOUT    (120) // 120 Seconds
static char is_keeplive_tmout(struct probe_mng_s *probe_mng)
{
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > probe_mng->keeplive_ts) {
        secs = current - probe_mng->keeplive_ts;
        if (secs >= __PROBE_KEEPLIVE_TIMEOUT) {
            probe_mng->keeplive_ts = current;
            return 1;
        }
    }
    return 0;
}

void run_probe_mng_daemon(struct probe_mng_s *probe_mng)
{
    int ret;

    for (;;) {
        if (probe_mng->snooper_proc_pb != NULL) {
            ret = perf_buffer__poll(probe_mng->snooper_proc_pb, THOUSAND);
            if (ret < 0) {
                break;
            }
        }

        if (probe_mng->snooper_cgrp_pb != NULL) {
            ret = perf_buffer__poll(probe_mng->snooper_cgrp_pb, THOUSAND);
            if (ret < 0) {
                break;
            }
        }

        if (is_keeplive_tmout(probe_mng)) {
            get_probemng_lock();
            keeplive_probes(probe_mng);
            put_probemng_lock();
        }
    }
}

