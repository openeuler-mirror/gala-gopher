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

#include "probe_mng.h"
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

u32 get_probe_status_flags(struct probe_s* probe)
{
    u32 probe_status_flags;
    (void)pthread_rwlock_rdlock(&probe->rwlock);
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
    free(probe);
    probe = NULL;
}

static struct probe_s* new_probe(const char* name, enum probe_type_e probe_type)
{
    struct probe_s *probe = NULL;
    probe = (struct probe_s *)malloc(sizeof(struct probe_s));
    if (probe == NULL) {
        return NULL;
    }

    memset(probe, 0, sizeof(struct probe_s));
    probe->name = strdup(name);

    int ret = pthread_rwlock_init(&probe->rwlock, NULL);
    if (ret) {
        goto err;
    }

    probe->fifo = FifoCreate(MAX_FIFO_SIZE);
    if (probe->fifo == NULL) {
        goto err;
    }
    probe->probe_type = probe_type;
    set_default_params(probe);
    return probe;

err:
    destroy_probe(probe);
    return NULL;
}

static int is_extend_probe(struct probe_s *probe)
{
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


static int check_probe_need_start(const char *check_cmd)
{
    /* ret val: 1 need start / 0 no need start */
    if (!check_cmd || !strlen(check_cmd)) {
        return 0;
    }

    int cnt = 0;
    FILE *fp = NULL;
    char data[MAX_COMMAND_LEN] = {0};
    fp = popen(check_cmd, "r");
    if (fp == NULL) {
        ERROR("popen error!(cmd = %s)\n", check_cmd);
        return 0;
    }

    if (fgets(data, sizeof(data), fp) != NULL) {
        cnt = atoi(data);
    }
    pclose(fp);

    return (cnt > 0);
}


#define EXTEND_PROBE_PROCID_CMD  "ps -ef | grep -w %s | grep -v grep | awk '{print $2}'"
static int get_extend_probe_pid(struct probe_s *probe)
{
    char cmd[COMMAND_LEN] = {0};
    char line[LINE_BUF_LEN] = {0};

    if (IS_NATIVE_PROBE(probe) || probe->bin == NULL) {
        return -1;
    }

    (void)snprintf(cmd, COMMAND_LEN, EXTEND_PROBE_PROCID_CMD, probe->bin);
    if (exec_cmd((const char *)cmd, line, LINE_BUF_LEN) < 0) {
        return -1;
    }
    return atoi(line);
}

static int start_probe(struct probe_s *probe)
{
    int ret;

    if (IS_RUNNING_PROBE(probe)) {
        ERROR("[PROBEMNG] Fail to start probe(name:%s) which is already running\n", probe->name);
        return -1;
    }

    if (!probe->cb) {
        return -1;
    }

    if (IS_NATIVE_PROBE(probe)) {
        if (probe->probe_entry == NULL) {
            ERROR("[PROBEMNG] Invalid entry for native probe(name: %s)\n", probe->name);
            return -1;
        }
    } else {
        if (probe->bin == NULL || access(probe->bin, 0) != 0) {
            ERROR("[PROBEMNG] Invalid executing bin file for probe(name: %s)\n", probe->name);
            return -1;
        }

        if (probe->fifo == NULL) {
            ERROR("[PROBEMNG] Fail to create fifo for probe(name: %s)\n", probe->name);
            return -1;
        }

        if (check_probe_need_start(probe->chk_cmd) != 1) {
            WARN("[PROBEMNG] Check command failed, skip starting probe(name: %s)\n", probe->name);
            return 0;
        }
    }

    // TODO: send snooper conf/params to probe

    ret = pthread_create(&probe->tid, NULL, probe->cb, probe);
    if (ret != 0) {
        ERROR("[PROBEMNG] Failed to create thread for probe(name: %s errno: %d).\n",
            probe->name, errno);
        return -1;
    }

    (void)pthread_detach(probe->tid);
    SET_PROBE_FLAGS(probe, PROBE_FLAGS_STARTED);
    UNSET_PROBE_FLAGS(probe, PROBE_FLAGS_STOPPING);
    return 0;
}

static int delete_probe(struct probe_s *probe)
{
    if (!IS_STOPPED_PROBE(probe)) {
        ERROR("[PROBEMNG] Fail to delete probe(name:%s) which has not been stopped\n", probe->name);
        return -1;
    }

    if (IS_NATIVE_PROBE(probe)) {
        ERROR("[PROBEMNG] Cannot delete native probe(name:%s)\n", probe->name);
        return -1;
    }

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

    if (IS_NATIVE_PROBE(probe)) {
        ERROR("[PROBEMNG] Cannot stop native probe(name:%s)\n", probe->name);
        return -1;
        // TODO: pthread_kill to native probe
    }

    if (IS_EXTEND_PROBE(probe)) {
        pid = get_extend_probe_pid(probe);
        if (pid < 0) {
            ERROR("[PROBEMNG] Fail to find process of extend probe(name:%s)\n", probe->name);
            return -1;
        }
        kill(pid, SIGINT);
    }

    SET_PROBE_FLAGS(probe, PROBE_FLAGS_STOPPING);
    UNSET_PROBE_FLAGS(probe, PROBE_FLAGS_STARTED);
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
    if (chkcmd_object == NULL) {
        return 0;
    }

    if (chkcmd_object->type != cJSON_String) {
        return -1;
    }
    set_probe_chk_cmd(probe, (const char *)chkcmd_object->valuestring);

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
    cJSON *json, *item;

    struct probe_s *probe = get_probe_by_name(probe_name);
    if (probe == NULL) {
        return -1;
    }
    json = cJSON_Parse(probe_content);
    if (json == NULL) {
        return -1;
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

    cJSON_Delete(json);
    return ret;
}

char *get_probe_json(const char *probe_name)
{
    cJSON *res, *item;
    char *buf;
    struct probe_s *probe;
    struct probe_parser_s *parser;
    enum probe_type_e probe_type = get_probe_type_by_name(probe_name);
    if (probe_type >= PROBE_TYPE_MAX) {
        return NULL;
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
    buf = cJSON_PrintUnformatted(res);
    cJSON_Delete(res);
    return buf;
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
    return g_probe_mng;
}

void destroy_probe_mng(void)
{
    struct probe_s *probe;

    if (g_probe_mng == NULL) {
        return;
    }

    for (int i = 0; i < PROBE_TYPE_MAX; i++) {
        destroy_probe(g_probe_mng->probes[i]);
        g_probe_mng->probes[i] = NULL;
    }

    free(g_probe_mng);
    g_probe_mng = NULL;
}

void New_DaemonKeeplive(int sig)
{
    int ret;
    struct probe_s *probe;

    for (int i = 0; i < PROBE_TYPE_MAX; i++) {
        probe = g_probe_mng->probes[i];
        if (probe == NULL || IS_NATIVE_PROBE(probe)) {
            continue;
        }

        /* probe has not been started or is stopping by user, skip keepaliving */
        if (IS_STOPPING_PROBE(probe) || !IS_STARTED_PROBE(probe)) {
            continue;
        }

        if (!IS_RUNNING_PROBE(probe)) {
            (void)pthread_create(&probe->tid, NULL, probe->cb, probe);
            (void)pthread_detach(probe->tid);

            INFO("[DAEMON] keepalive create probe(%s) thread.\n", probe->name);
            break;
        }
    }
}