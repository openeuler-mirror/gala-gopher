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
 * Description: snooper
 ******************************************************************************/
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <regex.h>
#include <cjson/cJSON.h>

#include "container.h"
#include "snooper.skel.h"
#include "probe_mng.h"

#include "snooper.h"

// Snooper obj name define
#define SNOOPER_OBJNAME_PROBE       "probe"
#define SNOOPER_OBJNAME_PROCID      "proc_id"
#define SNOOPER_OBJNAME_PROCNAME    "proc_name"
#define SNOOPER_OBJNAME_POD         "pod"
#define SNOOPER_OBJNAME_CONTAINERID "container_id"
#define SNOOPER_OBJNAME_GAUSSDB     "gaussdb"

// 'proc_name' snooper subobj name define'
/*
"proc_name": [
                {
                    "comm": "app1",
                    "cmdline": "",
                    "debuing_dir": ""
                },
                {
                    "comm": "app2",
                    "cmdline": "",
                    "debuing_dir": ""
                }
            ],
*/
#define SNOOPER_OBJNAME_COMM        "comm"
#define SNOOPER_OBJNAME_CMDLINE     "cmdline"
#define SNOOPER_OBJNAME_DBGDIR      "debugging_dir"

// 'gaussdb' snooper subobj name define
/*
"gaussdb": [
                {
                    "dbip": "192.168.1.1",
                    "dbport": 8080,
                    "dbname": "",
                    "dbuser": "",
                    "dbpass": ""
                },
                {
                    "dbip": "192.168.1.1",
                    "dbport": 8081,
                    "dbname": "",
                    "dbuser": "",
                    "dbpass": ""
                }
            ],
*/
#define SNOOPER_OBJNAME_DBIP        "dbip"
#define SNOOPER_OBJNAME_DBPORT      "dbport"
#define SNOOPER_OBJNAME_DBNAME      "dbname"
#define SNOOPER_OBJNAME_DBUSER      "dbuser"
#define SNOOPER_OBJNAME_DBPASS      "dbpass"

static struct probe_mng_s *__probe_mng_snooper = NULL;

struct probe_range_define_s {
    enum probe_type_e probe_type;
    char *desc;
    u32 flags;                      /* Refer to [PROBE] subprobe define. */
};

struct probe_range_define_s probe_range_define[] = {
    {PROBE_FG,     "oncpu",               PROBE_RANGE_ONCPU},
    {PROBE_FG,     "offcpu",              PROBE_RANGE_OFFCPU},
    {PROBE_FG,     "mem",                 PROBE_RANGE_MEM},

    {PROBE_L7,     "l7_bytes_metrics",    PROBE_RANGE_L7BYTES_METRICS},
    {PROBE_L7,     "l7_rpc_metrics",      PROBE_RANGE_L7RPC_METRICS},
    {PROBE_L7,     "l7_rpc_trace",        PROBE_RANGE_L7RPC_TRACE},

    {PROBE_TCP,    "tcp_abnormal",        PROBE_RANGE_TCP_ABNORMAL},
    {PROBE_TCP,    "tcp_rtt",             PROBE_RANGE_TCP_RTT},
    {PROBE_TCP,    "tcp_windows",         PROBE_RANGE_TCP_WINDOWS},
    {PROBE_TCP,    "tcp_srtt",            PROBE_RANGE_TCP_SRTT},
    {PROBE_TCP,    "tcp_rate",            PROBE_RANGE_TCP_RATE},
    {PROBE_TCP,    "tcp_sockbuf",         PROBE_RANGE_TCP_SOCKBUF},
    {PROBE_TCP,    "tcp_stats",           PROBE_RANGE_TCP_STATS},

    {PROBE_SOCKET, "tcp_socket",          PROBE_RANGE_SOCKET_TCP},
    {PROBE_SOCKET, "udp_socket",          PROBE_RANGE_SOCKET_UDP},

    {PROBE_IO,     "io_trace",            PROBE_RANGE_IO_TRACE},
    {PROBE_IO,     "io_err",              PROBE_RANGE_IO_ERR},
    {PROBE_IO,     "io_count",            PROBE_RANGE_IO_COUNT},
    {PROBE_IO,     "page_cache",          PROBE_RANGE_IO_PAGECACHE},

    {PROBE_PROC,   "base_metrics",        PROBE_RANGE_PROC_BASIC},
    {PROBE_PROC,   "proc_syscall",        PROBE_RANGE_PROC_SYSCALL},
    {PROBE_PROC,   "proc_fs",             PROBE_RANGE_PROC_FS},
    {PROBE_PROC,   "proc_io",             PROBE_RANGE_PROC_IO},
    {PROBE_PROC,   "proc_dns",            PROBE_RANGE_PROC_DNS},
    {PROBE_PROC,   "proc_pagecache",      PROBE_RANGE_PROC_PAGECACHE}
};

static int get_probe_range(const char *range)
{

    size_t size = sizeof(probe_range_define) / sizeof(struct probe_range_define_s);

    for (int i = 0; i < size; i++) {
        if (!strcasecmp(probe_range_define[i].desc, range)) {
            return probe_range_define[i].flags;
        }
    }

    return 0;
}

void free_snooper_conf(struct snooper_conf_s* snooper_conf)
{
    if (snooper_conf == NULL) {
        return;
    }

    if (snooper_conf->type = SNOOPER_CONF_APP) {
        if (snooper_conf->conf.app.cmdline) {
            (void)free(snooper_conf->conf.app.cmdline);
        }
        if (snooper_conf->conf.app.debuging_dir) {
            (void)free(snooper_conf->conf.app.debuging_dir);
        }
    }

    if (snooper_conf->type = SNOOPER_CONF_GAUSSDB) {
        if (snooper_conf->conf.gaussdb.dbname) {
            (void)free(snooper_conf->conf.gaussdb.dbname);
        }
        if (snooper_conf->conf.gaussdb.usr) {
            (void)free(snooper_conf->conf.gaussdb.usr);
        }
        if (snooper_conf->conf.gaussdb.pass) {
            (void)free(snooper_conf->conf.gaussdb.pass);
        }
        if (snooper_conf->conf.gaussdb.ip) {
            (void)free(snooper_conf->conf.gaussdb.ip);
        }
    }

    if (snooper_conf->type = SNOOPER_CONF_POD) {
        if (snooper_conf->conf.pod) {
            (void)free(snooper_conf->conf.pod);
        }
    }
    (void)free(snooper_conf);
    snooper_conf = NULL;
}


static struct snooper_conf_s* new_snooper_conf(void)
{
    struct snooper_conf_s* snooper_conf = (struct snooper_conf_s *)malloc(sizeof(struct snooper_conf_s));
    if (snooper_conf == NULL) {
        return NULL;
    }

    (void)memset(snooper_conf, 0, sizeof(struct snooper_conf_s));

    return snooper_conf;
}

static int add_snooper_conf_procid(struct probe_s *probe, u32 proc_id)
{
    if (probe->snooper_conf_num >= SNOOPER_MAX) {
        return -1;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }
    snooper_conf->type = SNOOPER_CONF_PROC_ID;
    snooper_conf->conf.proc_id = proc_id;

    if (probe->snooper_confs[probe->snooper_conf_num] != NULL) {
        free_snooper_conf(probe->snooper_confs[probe->snooper_conf_num]);
        probe->snooper_confs[probe->snooper_conf_num] = NULL;
    }

    probe->snooper_confs[probe->snooper_conf_num] = snooper_conf;
    probe->snooper_conf_num++;
    return 0;
}

static int add_snooper_conf_procname(struct probe_s *probe,
                            const char* comm, const char *cmdline, const char *dbgdir)
{
    if (probe->snooper_conf_num >= SNOOPER_MAX) {
        return -1;
    }

    if (comm[0] == 0) {
        return 0;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }

    (void)strncpy(snooper_conf->conf.app.comm, comm, TASK_COMM_LEN);
    if (cmdline && !(comm[0] != 0)) {
        snooper_conf->conf.app.cmdline = strdup(cmdline);
    }
    if (dbgdir && !(dbgdir[0] != 0)) {
        snooper_conf->conf.app.debuging_dir = strdup(dbgdir);
    }
    snooper_conf->type = SNOOPER_CONF_APP;

    if (probe->snooper_confs[probe->snooper_conf_num] != NULL) {
        free_snooper_conf(probe->snooper_confs[probe->snooper_conf_num]);
        probe->snooper_confs[probe->snooper_conf_num] = NULL;
    }

    probe->snooper_confs[probe->snooper_conf_num] = snooper_conf;
    probe->snooper_conf_num++;
    return 0;
}

static int add_snooper_conf_pod(struct probe_s *probe, const char* pod)
{
    if (probe->snooper_conf_num >= SNOOPER_MAX) {
        return -1;
    }
    if (pod[0] == 0) {
        return 0;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }

    snooper_conf->conf.pod = strdup(pod);
    snooper_conf->type = SNOOPER_CONF_POD;

    if (probe->snooper_confs[probe->snooper_conf_num] != NULL) {
        free_snooper_conf(probe->snooper_confs[probe->snooper_conf_num]);
        probe->snooper_confs[probe->snooper_conf_num] = NULL;
    }

    probe->snooper_confs[probe->snooper_conf_num] = snooper_conf;
    probe->snooper_conf_num++;
    return 0;
}

static int add_snooper_conf_container(struct probe_s *probe, const char* container_id)
{
    if (probe->snooper_conf_num >= SNOOPER_MAX) {
        return -1;
    }

    if (container_id[0] == 0) {
        return 0;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }

    (void)strncpy(snooper_conf->conf.container_id, container_id, CONTAINER_ABBR_ID_LEN);
    snooper_conf->type = SNOOPER_CONF_CONTAINER_ID;

    if (probe->snooper_confs[probe->snooper_conf_num] != NULL) {
        free_snooper_conf(probe->snooper_confs[probe->snooper_conf_num]);
        probe->snooper_confs[probe->snooper_conf_num] = NULL;
    }

    probe->snooper_confs[probe->snooper_conf_num] = snooper_conf;
    probe->snooper_conf_num++;
    return 0;
}

static int add_snooper_conf_gaussdb(struct probe_s *probe, char *ip, char *dbname,
                                                char *usr, char *pass, u32 port)
{
    if (probe->snooper_conf_num >= SNOOPER_MAX) {
        return -1;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }

    if (ip && !(ip[0] != 0)) {
        snooper_conf->conf.gaussdb.ip = strdup(ip);
    }
    if (dbname && !(dbname[0] != 0)) {
        snooper_conf->conf.gaussdb.dbname = strdup(dbname);
    }
    if (usr && !(usr[0] != 0)) {
        snooper_conf->conf.gaussdb.usr = strdup(usr);
    }
    if (pass && !(pass[0] != 0)) {
        snooper_conf->conf.gaussdb.pass = strdup(pass);
    }
    snooper_conf->conf.gaussdb.port = port;
    snooper_conf->type = SNOOPER_CONF_GAUSSDB;

    if (probe->snooper_confs[probe->snooper_conf_num] != NULL) {
        free_snooper_conf(probe->snooper_confs[probe->snooper_conf_num]);
        probe->snooper_confs[probe->snooper_conf_num] = NULL;
    }

    probe->snooper_confs[probe->snooper_conf_num] = snooper_conf;
    probe->snooper_conf_num++;
    return 0;
}

static void print_snooper_procid(struct probe_s *probe, cJSON *json)
{
    cJSON *procid_item;
    struct snooper_conf_s *snooper_conf;

    procid_item = cJSON_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_PROC_ID) {
            continue;
        }

        cJSON_AddItemToArray(procid_item, cJSON_CreateNumber(snooper_conf->conf.proc_id));
    }
    cJSON_AddItemToObject(json, SNOOPER_OBJNAME_PROCID, procid_item);
}

static int parse_snooper_procid(struct probe_s *probe, const cJSON *json)
{
    int ret;
    cJSON *procid_item, *object;

    procid_item = cJSON_GetObjectItem(json, SNOOPER_OBJNAME_PROCID);
    if (procid_item == NULL) {
        return 0;
    }

    size_t size = cJSON_GetArraySize(procid_item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(procid_item, i);
        if (object->type != cJSON_Number) {
            return -1;
        }

        ret = add_snooper_conf_procid(probe, (u32)object->valueint);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

/* {"probe":["XX","YY"]} , XX must be string but unsupported probe range will be ignored */
static int parse_snooper_probe(struct probe_s *probe, const cJSON *json)
{
    int ret;
    int range;
    cJSON *probe_item, *object;

    probe_item = cJSON_GetObjectItem(json, SNOOPER_OBJNAME_PROBE);
    if (probe_item == NULL) {
        return 0;
    }

    size_t size = cJSON_GetArraySize(probe_item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(probe_item, i);
        if (object->type != cJSON_String) {
            return -1;
        }

        range = get_probe_range((const char*)object->valuestring);
        probe->probe_range_flags |= range;
    }

    return 0;
}

static void print_snooper_procname(struct probe_s *probe, cJSON *json)
{
    cJSON *procname_item, *object;
    struct snooper_conf_s *snooper_conf;

    procname_item = cJSON_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_APP) {
            continue;
        }

        object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, SNOOPER_OBJNAME_COMM, snooper_conf->conf.app.comm);
        cJSON_AddStringToObject(object, SNOOPER_OBJNAME_CMDLINE, snooper_conf->conf.app.cmdline?:"");
        cJSON_AddStringToObject(object, SNOOPER_OBJNAME_DBGDIR, snooper_conf->conf.app.debuging_dir?:"");
        cJSON_AddItemToArray(procname_item, object);
    }
    cJSON_AddItemToObject(json, SNOOPER_OBJNAME_PROCNAME, procname_item);
}

static int parse_snooper_procname(struct probe_s *probe, const cJSON *json)
{
    int ret;
    cJSON *procname_item, *comm_item, *cmdline_item, *dbgdir_item, *object;
    char *comm, *cmdline, *dbgdir;

    procname_item = cJSON_GetObjectItem(json, SNOOPER_OBJNAME_PROCNAME);
    if (procname_item == NULL) {
        return 0;
    }

    size_t size = cJSON_GetArraySize(procname_item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(procname_item, i);

        comm_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_COMM);
        cmdline_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_CMDLINE);
        dbgdir_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_DBGDIR);

        if ((comm_item == NULL) || (comm_item->type != cJSON_String)) {
            return -1;
        }

        if (cmdline_item && (cmdline_item->type != cJSON_String)) {
            return -1;
        }

        if (dbgdir_item && (dbgdir_item->type != cJSON_String)) {
            return -1;
        }
        comm = (char *)comm_item->valuestring;
        cmdline = (cmdline_item != NULL) ? (char *)comm_item->valuestring : NULL;
        dbgdir = (dbgdir_item != NULL) ? (char *)dbgdir_item->valuestring : NULL;
        ret = add_snooper_conf_procname(probe, (const char *)comm, (const char *)cmdline, (const char *)dbgdir);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}


static void print_snooper_pod_container(struct probe_s *probe, cJSON *json)
{
    cJSON *pod_item, *cntr_item;
    struct snooper_conf_s *snooper_conf;

    pod_item = cJSON_CreateArray();
    cntr_item = cJSON_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type == SNOOPER_CONF_POD) {
            cJSON_AddItemToArray(pod_item, cJSON_CreateString(snooper_conf->conf.pod));
            continue;
        }

        if (snooper_conf->type == SNOOPER_CONF_CONTAINER_ID) {
            cJSON_AddItemToArray(cntr_item, cJSON_CreateString(snooper_conf->conf.container_id));
            continue;
        }
    }
    cJSON_AddItemToObject(json, SNOOPER_OBJNAME_POD, pod_item);
    cJSON_AddItemToObject(json, SNOOPER_OBJNAME_CONTAINERID, cntr_item);
}

static int parse_snooper_pod_container(struct probe_s *probe, const cJSON *json, const char *item_name)
{
    int ret;
    cJSON *item, *object;
    int pod_flag = 0;

    if (!strcasecmp(item_name, SNOOPER_OBJNAME_POD)) {
        pod_flag = 1;
    }

    item = cJSON_GetObjectItem(json, item_name);
    if (item == NULL) {
        return 0;
    }

    size_t size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(item, i);
        if (object->type != cJSON_String) {
            return -1;
        }
        if (pod_flag) {
            ret = add_snooper_conf_pod(probe, (const char *)object->valuestring);
        } else {
            ret = add_snooper_conf_container(probe, (const char *)object->valuestring);
        }
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static void print_snooper_gaussdb(struct probe_s *probe, cJSON *json)
{
    cJSON *gaussdb_item, *object;
    struct snooper_conf_s *snooper_conf;

    gaussdb_item = cJSON_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_GAUSSDB) {
            continue;
        }

        object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, SNOOPER_OBJNAME_DBIP, snooper_conf->conf.gaussdb.ip?:"");
        cJSON_AddNumberToObject(object, SNOOPER_OBJNAME_DBPORT, snooper_conf->conf.gaussdb.port);
        cJSON_AddStringToObject(object, SNOOPER_OBJNAME_DBNAME, snooper_conf->conf.gaussdb.dbname?:"");
        cJSON_AddStringToObject(object, SNOOPER_OBJNAME_DBUSER, snooper_conf->conf.gaussdb.usr?:"");
        cJSON_AddStringToObject(object, SNOOPER_OBJNAME_DBPASS, snooper_conf->conf.gaussdb.pass?:"");
        cJSON_AddItemToArray(gaussdb_item, object);
    }
    cJSON_AddItemToObject(json, SNOOPER_OBJNAME_GAUSSDB, gaussdb_item);
}

static int parse_snooper_gaussdb(struct probe_s *probe, const cJSON *json)
{
    int ret;
    cJSON *gaussdb_item, *ip_item, *dbname_item, *usr_item, *pass_item, *port_item, *object;
    char *ip, *dbname, *usr, *pass;

    gaussdb_item = cJSON_GetObjectItem(json, SNOOPER_OBJNAME_GAUSSDB);
    if (gaussdb_item == NULL) {
        return 0;
    }

    size_t size = cJSON_GetArraySize(gaussdb_item);
    for (int i = 0; i < size; i++) {
        object = cJSON_GetArrayItem(gaussdb_item, i);

        ip_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_DBIP);
        dbname_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_DBNAME);
        usr_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_DBUSER);
        pass_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_DBPASS);
        port_item = cJSON_GetObjectItem(object, SNOOPER_OBJNAME_DBPORT);

        if ((ip_item == NULL) || (ip_item->type != cJSON_String)) {
            return -1;
        }
        if ((dbname_item == NULL) || (dbname_item->type != cJSON_String)) {
            return -1;
        }
        if ((usr_item == NULL) || (usr_item->type != cJSON_String)) {
            return -1;
        }
        if ((pass_item == NULL) || (pass_item->type != cJSON_String)) {
            return -1;
        }
        if ((port_item == NULL) || (port_item->type != cJSON_Number)) {
            return -1;
        }

        ip = (char *)ip_item->valuestring;
        dbname = (char *)dbname_item->valuestring;
        usr = (char *)usr_item->valuestring;
        pass = (char *)pass_item->valuestring;
        ret = add_snooper_conf_gaussdb(probe, ip, dbname, usr, pass, (u32)port_item->valueint);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

void print_snooper(struct probe_s *probe, cJSON *json)
{
    cJSON *range;
    size_t size = sizeof(probe_range_define) / sizeof(struct probe_range_define_s);

    range = cJSON_CreateArray();
    for (int i = 0; i < size; i++) {
        if (probe->probe_type == probe_range_define[i].probe_type) {
            if (probe->probe_range_flags & probe_range_define[i].flags) {
                cJSON_AddItemToArray(range, cJSON_CreateString(probe_range_define[i].desc));
            }
        }
    }
    cJSON_AddItemToObject(json, SNOOPER_OBJNAME_PROBE, range);

    print_snooper_procid(probe, json);
    print_snooper_procname(probe, json);
    print_snooper_pod_container(probe, json);
    print_snooper_gaussdb(probe, json);
}

static int send_snooper_conf(struct probe_s *probe)
{
    //TODO: refresh and send snooper obj to probe by ipc msg
    return 0;
}

//TODO: refactor this func
int parse_snooper(struct probe_s *probe, const cJSON *json)
{
    int i;
#if 0
    u32 probe_range_flags_bak;
    u32 snooper_conf_num_bak = probe->snooper_conf_num;
    struct snooper_conf_s *snooper_confs_bak[SNOOPER_MAX] = {0};

    /* Backup and clear current snooper config*/
    probe_range_flags_bak = probe->probe_range_flags;

    snooper_conf_num_bak = probe->snooper_conf_num;
    probe->snooper_conf_num = 0;
    (void)memcpy(&snooper_confs_bak, &probe->snooper_confs, snooper_conf_num_bak * (sizeof(struct snooper_conf_s *)));
    (void)memset(&probe->snooper_confs, 0, snooper_conf_num_bak * (sizeof(struct snooper_conf_s *)));
#endif

    /* free current snooper config */
    for (i = 0 ; i < probe->snooper_conf_num ; i++) {
        free_snooper_conf(probe->snooper_confs[i]);
        probe->snooper_confs[i] = NULL;
    }
    probe->snooper_conf_num = 0;
    probe->probe_range_flags = 0;
    if (parse_snooper_probe(probe, json)) {
        ERROR("[PROBEMNG] Failed to parse range for probe(%s)\n", probe->name);
        return -1;
    }

    if (parse_snooper_procid(probe, json)) {
        ERROR("[PROBEMNG] Failed to parse proc id for probe(name:%s)\n", probe->name);
        return -1;
    }

    if (parse_snooper_procname(probe, json)) {
        ERROR("[PROBEMNG] Failed to parse proc id for probe(name:%s)\n", probe->name);
        return -1;
    }

    if (parse_snooper_pod_container(probe, json, SNOOPER_OBJNAME_POD)) {
        ERROR("[PROBEMNG] Failed to parse podname for probe(name:%s)\n", probe->name);
        return -1;
    }

    if (parse_snooper_pod_container(probe, json, SNOOPER_OBJNAME_CONTAINERID)) {
        ERROR("[PROBEMNG] Failed to parse container id for probe(name:%s)\n", probe->name);
        return -1;
    }

    if (parse_snooper_gaussdb(probe, json)) {
        ERROR("[PROBEMNG] Failed to parse gaussdb info for probe(name:%s)\n", probe->name);
        return -1;
    }

    return send_snooper_conf(probe);
#if 0
resume_snooper:
    for (i = 0 ; i < snooper_conf_num_bak ; i++) {
        free_snooper_conf(probe->snooper_confs[i]);
        probe->snooper_confs[i] = snooper_confs_bak[i];
    }
    probe->snooper_conf_num = snooper_conf_num_bak;

resume_range:
    probe->probe_range_flags = probe_range_flags_bak;
    return -1;
#endif
}

void free_snooper_obj(struct snooper_obj_s* snooper_obj)
{
    if (snooper_obj == NULL) {
        return;
    }

    if (snooper_obj->type = SNOOPER_OBJ_GAUSSDB) {
        if (snooper_obj->obj.gaussdb.dbname) {
            (void)free(snooper_obj->obj.gaussdb.dbname);
        }
        if (snooper_obj->obj.gaussdb.usr) {
            (void)free(snooper_obj->obj.gaussdb.usr);
        }
        if (snooper_obj->obj.gaussdb.pass) {
            (void)free(snooper_obj->obj.gaussdb.pass);
        }
        if (snooper_obj->obj.gaussdb.ip) {
            (void)free(snooper_obj->obj.gaussdb.ip);
        }
    }
    (void)free(snooper_obj);
    snooper_obj = NULL;
}

static struct snooper_obj_s* new_snooper_obj(void)
{
    struct snooper_obj_s* snooper_obj = (struct snooper_obj_s *)malloc(sizeof(struct snooper_obj_s));
    if (snooper_obj == NULL) {
        return NULL;
    }

    (void)memset(snooper_obj, 0, sizeof(struct snooper_obj_s));

    return snooper_obj;
}

