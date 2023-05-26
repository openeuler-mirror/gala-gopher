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

#include "bpf.h"
#include "container.h"
#include "probe_mng.h"
#include "pod_mng.h"

#include "ipc.h"
#include "snooper.h"
#include "snooper.skel.h"
#include "snooper_bpf.h"

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
    {PROBE_FG,     "io",                  PROBE_RANGE_IO},

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

    {PROBE_PROC,   "proc_syscall",        PROBE_RANGE_PROC_SYSCALL},
    {PROBE_PROC,   "proc_fs",             PROBE_RANGE_PROC_FS},
    {PROBE_PROC,   "proc_dns",            PROBE_RANGE_PROC_DNS},
    {PROBE_PROC,   "proc_io",             PROBE_RANGE_PROC_IO},
    {PROBE_PROC,   "proc_pagecache",      PROBE_RANGE_PROC_PAGECACHE},
    {PROBE_PROC,   "proc_net",            PROBE_RANGE_PROC_NET},
    {PROBE_PROC,   "proc_offcpu",         PROBE_RANGE_PROC_OFFCPU},

    {PROBE_BASEINFO,  "cpu",              PROBE_RANGE_SYS_CPU},
    {PROBE_BASEINFO,  "mem",              PROBE_RANGE_SYS_MEM},
    {PROBE_BASEINFO,  "nic",              PROBE_RANGE_SYS_NIC},
    {PROBE_BASEINFO,  "net",              PROBE_RANGE_SYS_NET},
    {PROBE_BASEINFO,  "disk",             PROBE_RANGE_SYS_DISK},
    {PROBE_BASEINFO,  "fs",               PROBE_RANGE_SYS_FS},
    {PROBE_BASEINFO,  "proc",             PROBE_RANGE_SYS_PROC},
    {PROBE_BASEINFO,  "host",             PROBE_RANGE_SYS_HOST},

    {PROBE_TP,     "oncpu",               PROBE_RANGE_TPROFILING_ONCPU},
    {PROBE_TP,     "syscall_file",        PROBE_RANGE_TPROFILING_SYSCALL_FILE},
    {PROBE_TP,     "syscall_net",        PROBE_RANGE_TPROFILING_SYSCALL_NET},
    {PROBE_TP,     "syscall_lock",        PROBE_RANGE_TPROFILING_SYSCALL_LOCK},
    {PROBE_TP,     "syscall_sched",        PROBE_RANGE_TPROFILING_SYSCALL_SCHED},
};

static void refresh_snooper_obj(struct probe_s *probe);

void get_probemng_lock(void);
void put_probemng_lock(void);
static int get_probe_range(enum probe_type_e probe_type, const char *range)
{

    size_t size = sizeof(probe_range_define) / sizeof(struct probe_range_define_s);

    for (int i = 0; i < size; i++) {
        if (probe_range_define[i].probe_type == probe_type && !strcasecmp(probe_range_define[i].desc, range)) {
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

    if (snooper_conf->type == SNOOPER_CONF_APP) {
        if (snooper_conf->conf.app.cmdline) {
            (void)free(snooper_conf->conf.app.cmdline);
        }
        if (snooper_conf->conf.app.debuging_dir) {
            (void)free(snooper_conf->conf.app.debuging_dir);
        }
    }

    if (snooper_conf->type == SNOOPER_CONF_GAUSSDB) {
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

    if (snooper_conf->type == SNOOPER_CONF_POD) {
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

        range = get_probe_range(probe->probe_type, (const char*)object->valuestring);
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

static void __build_ipc_body(struct probe_s *probe, struct ipc_body_s* ipc_body)
{
    ipc_body->snooper_obj_num = 0;

    for (int i = 0; i < SNOOPER_MAX; i++) {
        if (probe->snooper_objs[i] == NULL) {
            continue;
        }

        memcpy(&(ipc_body->snooper_objs[ipc_body->snooper_obj_num]),
                probe->snooper_objs[i], sizeof(struct snooper_obj_s));

        ipc_body->snooper_obj_num++;
    }

    ipc_body->probe_range_flags = probe->probe_range_flags;
    memcpy(&(ipc_body->probe_param), &probe->probe_param, sizeof(struct probe_params));
}

int send_snooper_obj(struct probe_s *probe)
{
    struct ipc_body_s ipc_body; // Initialized at '__build_ipc_body' function

    if (!probe || !IS_STARTED_PROBE(probe)) {
        return 0;
    }

    __build_ipc_body(probe, &ipc_body);
    return send_ipc_msg(__probe_mng_snooper->msq_id, (long)probe->probe_type, &ipc_body);
}

int parse_snooper(struct probe_s *probe, const cJSON *json)
{
    int i;

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

    refresh_snooper_obj(probe);
    return 0;
}

void free_snooper_obj(struct snooper_obj_s* snooper_obj)
{
    if (snooper_obj == NULL) {
        return;
    }

    if (snooper_obj->type == SNOOPER_OBJ_GAUSSDB) {
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

    if (snooper_obj->type == SNOOPER_OBJ_CON) {
        if (snooper_obj->obj.con_info.con_id) {
            (void)free(snooper_obj->obj.con_info.con_id);
        }
        if (snooper_obj->obj.con_info.container_name) {
            (void)free(snooper_obj->obj.con_info.container_name);
        }
        if (snooper_obj->obj.con_info.libc_path) {
            (void)free(snooper_obj->obj.con_info.libc_path);
        }
        if (snooper_obj->obj.con_info.libssl_path) {
            (void)free(snooper_obj->obj.con_info.libssl_path);
        }
        if (snooper_obj->obj.con_info.pod_id) {
            (void)free(snooper_obj->obj.con_info.pod_id);
        }
        if (snooper_obj->obj.con_info.pod_name) {
            (void)free(snooper_obj->obj.con_info.pod_name);
        }
        if (snooper_obj->obj.con_info.pod_ip_str) {
            (void)free(snooper_obj->obj.con_info.pod_ip_str);
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

void backup_snooper(struct probe_s *probe, struct probe_s *probe_backup)
{
    u32 snooper_conf_num = probe->snooper_conf_num;

    probe_backup->snooper_conf_num = snooper_conf_num;
    probe_backup->probe_range_flags = probe->probe_range_flags;

    (void)memcpy(&probe_backup->snooper_confs, &probe->snooper_confs,
                    SNOOPER_MAX * (sizeof(struct snooper_conf_s *)));
    (void)memset(&probe->snooper_confs, 0, SNOOPER_MAX * (sizeof(struct snooper_conf_s *)));

    (void)memcpy(&probe_backup->snooper_objs, &probe->snooper_objs,
                    SNOOPER_MAX * (sizeof(struct snooper_obj_s *)));
    (void)memset(&probe->snooper_objs, 0, SNOOPER_MAX * (sizeof(struct snooper_obj_s *)));
}

void rollback_snooper(struct probe_s *probe, struct probe_s *probe_backup)
{
    int i;

    probe->probe_range_flags = probe_backup->probe_range_flags;

    for (i = 0 ; i < SNOOPER_MAX; i++) {
        free_snooper_conf(probe->snooper_confs[i]);
        probe->snooper_confs[i] = probe_backup->snooper_confs[i];
        probe_backup->snooper_confs[i] = NULL;

        free_snooper_obj(probe->snooper_objs[i]);
        probe->snooper_objs[i] = probe_backup->snooper_objs[i];
        probe_backup->snooper_objs[i] = NULL;
    }

    probe->snooper_conf_num = probe_backup->snooper_conf_num;
    probe_backup->snooper_conf_num = 0;
}

#define __SYS_PROC_DIR  "/proc"
static inline char __is_proc_dir(const char *dir_name)
{
    if (dir_name[0] >= '1' && dir_name[0] <= '9') {
        return 1;
    }
    return 0;
}

static char __chk_snooper_pattern(const char *conf_pattern, const char *target)
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

#define __SYS_PROC_COMM             "/proc/%s/comm"
#define __CAT_SYS_PROC_COMM         "/usr/bin/cat /proc/%s/comm 2> /dev/null"
#define __PROC_NAME_MAX             64
#define __PROC_CMDLINE_MAX          4096
static int __read_proc_comm(const char *dir_name, char *comm, size_t size)
{
    char proc_comm_path[PATH_LEN];
    char cat_comm_cmd[COMMAND_LEN];

    proc_comm_path[0] = 0;
    (void)snprintf(proc_comm_path, PATH_LEN, __SYS_PROC_COMM, dir_name);
    if (access((const char *)proc_comm_path, 0) != 0) {
        return -1;
    }

    cat_comm_cmd[0] = 0;
    (void)snprintf(cat_comm_cmd, COMMAND_LEN, __CAT_SYS_PROC_COMM, dir_name);

    return exec_cmd((const char *)cat_comm_cmd, comm, size);
}

#define __SYS_PROC_CMDLINE          "/proc/%s/cmdline"
static int __read_proc_cmdline(const char *dir_name, char *cmdline, u32 size)
{
    FILE *f = NULL;
    char path[LINE_BUF_LEN];
    int index = 0;

    path[0] = 0;
    (void)snprintf(path, LINE_BUF_LEN, __SYS_PROC_CMDLINE, dir_name);
    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    /* parse line */
    while (!feof(f)) {
        if (index >= size - 1) {
            cmdline[index] = '\0';
            break;
        }
        cmdline[index] = fgetc(f);
        if (cmdline[index] == '\"') {
            if (index > size -2) {
                cmdline[index] = '\0';
                break;
            } else {
                cmdline[index] = '\\';
                cmdline[index + 1] =  '\"';
                index++;
            }
        } else if (cmdline[index] == '\0') {
            cmdline[index] = ' ';
        } else if (cmdline[index] == EOF) {
            cmdline[index] = '\0';
        }
        index++;
    }

    cmdline[index] = 0;

    (void)fclose(f);
    return 0;
}

static int __get_snooper_obj_idle(struct probe_s *probe, size_t size)
{
    int pos = -1;
    for (int i = 0; i < size; i++) {
        if (probe->snooper_objs[i] == NULL) {
            pos = i;
            break;
        }
    }
    return pos;
}

static int add_snooper_obj_procid(struct probe_s *probe, u32 proc_id)
{
    int pos = __get_snooper_obj_idle(probe, SNOOPER_MAX);
    if (pos < 0) {
        return -1;
    }

    struct snooper_obj_s* snooper_obj = new_snooper_obj();
    if (snooper_obj == NULL) {
        return -1;
    }
    snooper_obj->type = SNOOPER_OBJ_PROC;
    snooper_obj->obj.proc.proc_id = proc_id;

    probe->snooper_objs[pos] = snooper_obj;
    return 0;
}

static int add_snooper_obj_con_info(struct probe_s *probe, struct con_info_s *con_info)
{
    int pos = __get_snooper_obj_idle(probe, SNOOPER_MAX);
    if (pos < 0) {
        return -1;
    }

    struct snooper_obj_s* snooper_obj = new_snooper_obj();
    if (snooper_obj == NULL) {
        return -1;
    }
    if (con_info == NULL) {
        return -1;
    }
    snooper_obj->type = SNOOPER_OBJ_CON;
    snooper_obj->obj.con_info.flags = con_info->flags;
    snooper_obj->obj.con_info.cpucg_inode = con_info->cpucg_inode;
    if (con_info->con_id) {
        snooper_obj->obj.con_info.con_id = strdup(con_info->con_id);
    }
    if (con_info->container_name) {
        snooper_obj->obj.con_info.container_name = strdup(con_info->container_name);
    }
    if (con_info->libc_path) {
        snooper_obj->obj.con_info.libc_path = strdup(con_info->libc_path);
    }
    if (con_info->libssl_path) {
        snooper_obj->obj.con_info.libssl_path = strdup(con_info->libssl_path);
    }
    if (con_info->pod_info_ptr) {
        if (con_info->pod_info_ptr->pod_id) {
            snooper_obj->obj.con_info.pod_id = strdup(con_info->pod_info_ptr->pod_id);
        }
        if (con_info->pod_info_ptr->pod_name) {
            snooper_obj->obj.con_info.pod_name = strdup(con_info->pod_info_ptr->pod_name);
        }
        if (con_info->pod_info_ptr->pod_ip_str) {
            snooper_obj->obj.con_info.pod_ip_str = strdup(con_info->pod_info_ptr->pod_ip_str);
        }
    }

    probe->snooper_objs[pos] = snooper_obj;
    return 0;
}

static int add_snooper_obj_gaussdb(struct probe_s *probe, struct snooper_gaussdb_s *db_param)
{
    int pos = __get_snooper_obj_idle(probe, SNOOPER_MAX);
    if (pos < 0) {
        return -1;
    }

    struct snooper_obj_s* snooper_obj = new_snooper_obj();
    if (snooper_obj == NULL) {
        return -1;
    }

    snooper_obj->type = SNOOPER_OBJ_GAUSSDB;
    if (db_param->ip) {
        snooper_obj->obj.gaussdb.ip = strdup(db_param->ip);
    }
    if (db_param->dbname) {
        snooper_obj->obj.gaussdb.dbname = strdup(db_param->dbname);
    }
    if (db_param->usr) {
        snooper_obj->obj.gaussdb.usr = strdup(db_param->usr);
    }
    if (db_param->pass) {
        snooper_obj->obj.gaussdb.pass = strdup(db_param->pass);
    }
    snooper_obj->obj.gaussdb.port = db_param->port;

    probe->snooper_objs[pos] = snooper_obj;
    return 0;
}

static int gen_snooper_by_procname(struct probe_s *probe, struct snooper_conf_s *snooper_conf)
{
    int ret;
    DIR *dir = NULL;
    struct dirent *entry;
    char comm[__PROC_NAME_MAX];
    char cmdline[__PROC_CMDLINE_MAX];

    if (snooper_conf->type != SNOOPER_CONF_APP) {
        return 0;
    }

    dir = opendir(__SYS_PROC_DIR);
    if (dir == NULL) {
        return -1;
    }

    do {
        entry = readdir(dir);
        if (entry == NULL) {
            break;
        }
        if (!__is_proc_dir(entry->d_name) == -1) {
            continue;
        }

        comm[0] = 0;
        ret = __read_proc_comm(entry->d_name, comm, __PROC_NAME_MAX);
        if (ret) {
            continue;
        }

        if (!__chk_snooper_pattern((const char *)snooper_conf->conf.app.comm, (const char *)comm)) {
            // 'comm' Unmatched
            continue;
        }

        if (snooper_conf->conf.app.cmdline != NULL) {
            cmdline[0] = 0;
            ret = __read_proc_cmdline(entry->d_name, cmdline, __PROC_CMDLINE_MAX);
            if (ret) {
                continue;
            }

            if (strstr(cmdline, snooper_conf->conf.app.cmdline) == NULL) {
                // 'cmdline' Unmatched
                continue;
            }
        }

        // Well matched
        (void)add_snooper_obj_procid(probe, (u32)atoi(entry->d_name));
    } while (1);

    closedir(dir);
    return 0;
}

static int gen_snooper_by_procid(struct probe_s *probe, struct snooper_conf_s *snooper_conf)
{
    if (snooper_conf->type != SNOOPER_CONF_PROC_ID) {
        return 0;
    }

    return add_snooper_obj_procid(probe, snooper_conf->conf.proc_id);
}

static int gen_snooper_by_container(struct probe_s *probe, struct snooper_conf_s *snooper_conf)
{
    if (snooper_conf->type != SNOOPER_CONF_CONTAINER_ID || snooper_conf->conf.container_id[0] == 0) {
        return 0;
    }

    struct con_info_s *con_info = get_and_add_con_info(FAKE_POD_ID, snooper_conf->conf.container_id);
    if (con_info == NULL) {
        return -1;
    }

    return add_snooper_obj_con_info(probe, con_info);
}

static int gen_snooper_by_pod(struct probe_s *probe, struct snooper_conf_s *snooper_conf)
{
    if (snooper_conf->type != SNOOPER_CONF_POD || snooper_conf->conf.pod == NULL) {
        return 0;
    }

    struct pod_info_s *pod_info = get_and_add_pod_info(snooper_conf->conf.pod);
    if (pod_info == NULL) {
        return -1;
    }

    if (pod_info->con_head == NULL) {
        return 0;
    }

    struct containers_hash_t *con, *tmp;
    struct con_info_s *con_info;
    if (H_COUNT(pod_info->con_head) > 0) {
        H_ITER(pod_info->con_head, con, tmp) {
            add_snooper_obj_con_info(probe, &con->con_info);
        }
    }

    return 0;
}

static int gen_snooper_by_gaussdb(struct probe_s *probe, struct snooper_conf_s *snooper_conf)
{
    if (snooper_conf->type != SNOOPER_CONF_GAUSSDB) {
        return 0;
    }

    return add_snooper_obj_gaussdb(probe, &(snooper_conf->conf.gaussdb));
}

typedef int (*probe_snooper_generator)(struct probe_s *, struct snooper_conf_s *);
struct snooper_generator_s {
    enum snooper_conf_e type;
    probe_snooper_generator generator;
};
struct snooper_generator_s snooper_generators[] = {
    {SNOOPER_CONF_APP,           gen_snooper_by_procname   },
    {SNOOPER_CONF_GAUSSDB,       gen_snooper_by_gaussdb    },
    {SNOOPER_CONF_PROC_ID,       gen_snooper_by_procid     },
    {SNOOPER_CONF_POD,           gen_snooper_by_pod        },
    {SNOOPER_CONF_CONTAINER_ID,  gen_snooper_by_container  }
};

/* Flush current snooper obj and re-generate */
static void refresh_snooper_obj(struct probe_s *probe)
{
    int i,j;
    struct snooper_conf_s * snooper_conf;
    struct snooper_generator_s *generator;
    size_t size = sizeof(snooper_generators) / sizeof(struct snooper_generator_s);

    for (i = 0 ; i < SNOOPER_MAX ; i++) {
        free_snooper_obj(probe->snooper_objs[i]);
        probe->snooper_objs[i] = NULL;
    }

    for (i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        for (j = 0; j < size ; j++) {
            if (snooper_conf->type == snooper_generators[j].type) {
                generator = &(snooper_generators[j]);
                if (generator->generator(probe, snooper_conf)) {
                    return;
                }
                break;
            }
        }

    }
}

static void __rcv_snooper_proc_exec(struct probe_mng_s *probe_mng, const char* comm, u32 proc_id)
{
    int i, j;
    char snooper_obj_added;
    struct probe_s *probe;
    struct snooper_conf_s *snooper_conf;
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char pod_name[POD_NAME_LEN + 1];
    char pid_str[INT_LEN + 1];

    pid_str[0] = 0;
    (void)snprintf(pid_str, INT_LEN + 1, "%u", proc_id);

    container_id[0] = 0;
    pod_name[0] = 0;
    (void)get_container_id_by_pid_cpuset(pid_str, container_id, CONTAINER_ABBR_ID_LEN + 1);
    if (container_id[0] != 0) {
        (void)get_container_pod((const char *)container_id, pod_name, POD_NAME_LEN + 1);
    }

    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        probe = probe_mng->probes[i];
        if (!probe) {
            continue;
        }

        snooper_obj_added = 0;
        for (j = 0; j < probe->snooper_conf_num && j < SNOOPER_MAX; j++) {
            snooper_conf = probe->snooper_confs[j];
            if (snooper_conf && snooper_conf->type == SNOOPER_CONF_APP) {
                if (__chk_snooper_pattern((const char *)(snooper_conf->conf.app.comm), comm)) {
                    (void)add_snooper_obj_procid(probe, proc_id);
                    snooper_obj_added = 1;
                }
            }
            if (snooper_conf && snooper_conf->type == SNOOPER_CONF_CONTAINER_ID) {
                if (container_id[0] != 0 && !strcasecmp(container_id, snooper_conf->conf.container_id)) {
                    (void)add_snooper_obj_procid(probe, proc_id);
                    snooper_obj_added = 1;
                }
            }
            if (snooper_conf && snooper_conf->type == SNOOPER_CONF_POD) {
                if (pod_name[0] != 0
                    && snooper_conf->conf.pod != NULL
                    && !strcasecmp(pod_name, snooper_conf->conf.pod)) {
                    (void)add_snooper_obj_procid(probe, proc_id);
                    snooper_obj_added = 1;
                }
            }
        }

        if (snooper_obj_added) {
            (void)send_snooper_obj(probe);
        }
    }
}

static void __rcv_snooper_proc_exit(struct probe_mng_s *probe_mng, u32 proc_id)
{
    char snooper_obj_removed;
    int i, j;
    struct probe_s *probe;
    struct snooper_obj_s *snooper_obj;

    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        probe = probe_mng->probes[i];
        if (!probe) {
            continue;
        }

        snooper_obj_removed = 0;
        for (j = 0; j < SNOOPER_MAX; j++) {
            snooper_obj = probe->snooper_objs[j];
            if (!snooper_obj || snooper_obj->type != SNOOPER_OBJ_PROC) {
                continue;
            }

            if (snooper_obj->obj.proc.proc_id == proc_id) {
                free_snooper_obj(snooper_obj);
                probe->snooper_objs[j] = NULL;
                snooper_obj = NULL;
                snooper_obj_removed = 1;
            }
        }

        if (snooper_obj_removed) {
            (void)send_snooper_obj(probe);
        }
    }
}

static void rcv_snooper_proc_evt(void *ctx, int cpu, void *data, __u32 size)
{
    struct snooper_proc_evt_s *evt = data;
    char comm[TASK_COMM_LEN];

    comm[0] = 0;
    char *p = strrchr(evt->filename, '/');
    if (p) {
        strncpy(comm, p + 1, TASK_COMM_LEN - 1);
    } else {
        strncpy(comm, evt->filename, TASK_COMM_LEN - 1);
    }

    get_probemng_lock();

    if (evt->proc_event == PROC_EXEC) {
        __rcv_snooper_proc_exec(__probe_mng_snooper, (const char *)comm, (u32)evt->pid);
    } else {
        __rcv_snooper_proc_exit(__probe_mng_snooper, (u32)evt->pid);
    }
    put_probemng_lock();
}

static void __rcv_snooper_cgrp_exec(struct probe_mng_s *probe_mng, char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    char snooper_obj_added;
    int i, j;
    char pod_name[POD_NAME_LEN] = {0};
    struct probe_s *probe;
    struct snooper_conf_s *snooper_conf;
    struct con_info_s *con_info = get_con_info(pod_id, con_id);
    if (con_info == NULL || con_info->pod_info_ptr == NULL) {
        return;
    }

    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        probe = probe_mng->probes[i];
        if (!probe) {
            continue;
        }

        snooper_obj_added = 0;
        for (j = 0; j < probe->snooper_conf_num && j < SNOOPER_MAX; j++) {
            snooper_conf = probe->snooper_confs[j];
            if (!snooper_conf) {
                continue;
            }
            if (snooper_conf->type == SNOOPER_CONF_POD) {
                strncpy(pod_name, snooper_conf->conf.pod, POD_NAME_LEN - 1);
                pod_name[POD_NAME_LEN - 1] = 0;
                if (strstr(con_info->pod_info_ptr->pod_name, pod_name) != NULL) {
                    add_snooper_obj_con_info(probe, con_info);
                    snooper_obj_added = 1;
                }
            } else if (snooper_conf->type == SNOOPER_CONF_CONTAINER_ID) {
                if (strstr(con_info->con_id, snooper_conf->conf.container_id) != NULL) {
                    add_snooper_obj_con_info(probe, con_info);
                    snooper_obj_added = 1;
                }
            }
        }

        if (snooper_obj_added) {
            (void)send_snooper_obj(probe);
        }
    }
}

static void __rcv_snooper_cgrp_exit(struct probe_mng_s *probe_mng, char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    char snooper_obj_removed;
    int i, j;
    struct probe_s *probe;
    struct snooper_obj_s *snooper_obj;

    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        probe = probe_mng->probes[i];
        if (!probe) {
            continue;
        }

        snooper_obj_removed = 0;
        for (j = 0; j < SNOOPER_MAX; j++) {
            snooper_obj = probe->snooper_objs[j];
            if (!snooper_obj || snooper_obj->type != SNOOPER_OBJ_CON) {
                continue;
            }

            if (strcmp(snooper_obj->obj.con_info.con_id, con_id) == 0) {
                free_snooper_obj(snooper_obj);
                probe->snooper_objs[j] = NULL;
                snooper_obj = NULL;
                snooper_obj_removed = 1;
            }
        }

        if (snooper_obj_removed) {
            (void)send_snooper_obj(probe);
        }
    }
}

static void rcv_snooper_cgrp_evt(void *ctx, int cpu, void *data, __u32 size)
{
    struct snooper_cgrp_evt_s *msg_data = (struct snooper_cgrp_evt_s *)data;

    char pod_id[POD_ID_LEN + 1] = {0};
    char con_id[CONTAINER_ABBR_ID_LEN + 1] = {0};
    struct pods_hash_t *pod = NULL;
    enum id_ret_t id_ret = get_pod_container_id(msg_data->cgrp_path, pod_id, con_id);

    if (id_ret == ID_FAILED) {
        return;
    }

    if (msg_data->cgrp_event == CGRP_MK) {
        cgrp_mk_process(pod_id, con_id, id_ret);
        if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
            get_probemng_lock();
            __rcv_snooper_cgrp_exec(__probe_mng_snooper, pod_id, con_id, id_ret);
            put_probemng_lock();
        }
    } else {
        cgrp_rm_process(pod_id, con_id, id_ret);
        if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
            get_probemng_lock();
            __rcv_snooper_cgrp_exit(__probe_mng_snooper, pod_id, con_id, id_ret);
            put_probemng_lock();
        }

    }

    return;
}

static void loss_data(void *ctx, int cpu, u64 cnt)
{
    // TODO: debuging
}

int load_snooper_bpf(struct probe_mng_s *probe_mng)
{
    int ret = 0;
    struct snooper_bpf *snooper_skel;

    __probe_mng_snooper = probe_mng;

    INIT_BPF_APP(snooper, EBPF_RLIM_LIMITED);

    /* Open load and verify BPF application */
    snooper_skel = snooper_bpf__open();
    if (!snooper_skel) {
        ret = -1;
        ERROR("Failed to open BPF snooper_skel.\n");
        goto end;
    }

    if (snooper_bpf__load(snooper_skel)) {
        ret = -1;
        ERROR("Failed to load BPF snooper_skel.\n");
        goto end;
    }

    /* Attach tracepoint handler */
    ret = snooper_bpf__attach(snooper_skel);
    if (ret) {
        ERROR("Failed to attach BPF snooper_skel.\n");
        goto end;
    }
    INFO("Succeed to load and attach BPF snooper_skel.\n");

    probe_mng->snooper_proc_pb = create_pref_buffer2(GET_MAP_FD(snooper, snooper_proc_channel),
                                                        rcv_snooper_proc_evt, loss_data);
    probe_mng->snooper_cgrp_pb = create_pref_buffer2(GET_MAP_FD(snooper, snooper_cgrp_channel),
                                                        rcv_snooper_cgrp_evt, loss_data);
    probe_mng->snooper_skel = snooper_skel;

    if (probe_mng->snooper_proc_pb == NULL || probe_mng->snooper_cgrp_pb == NULL) {
        ret = -1;
        goto end;
    }

    return 0;

end:
    if (snooper_skel) {
        snooper_bpf__destroy(snooper_skel);
        probe_mng->snooper_skel = NULL;
    }

    if (probe_mng->snooper_proc_pb) {
        perf_buffer__free(probe_mng->snooper_proc_pb);
        probe_mng->snooper_proc_pb = NULL;
    }
    if (probe_mng->snooper_cgrp_pb) {
        perf_buffer__free(probe_mng->snooper_cgrp_pb);
        probe_mng->snooper_cgrp_pb = NULL;
    }
    return ret;
}

void unload_snooper_bpf(struct probe_mng_s *probe_mng)
{
    if (probe_mng->snooper_skel) {
        snooper_bpf__destroy(probe_mng->snooper_skel);
        probe_mng->snooper_skel = NULL;
    }

    if (probe_mng->snooper_proc_pb) {
        perf_buffer__free(probe_mng->snooper_proc_pb);
        probe_mng->snooper_proc_pb = NULL;
    }
    if (probe_mng->snooper_cgrp_pb) {
        perf_buffer__free(probe_mng->snooper_cgrp_pb);
        probe_mng->snooper_cgrp_pb = NULL;
    }
    __probe_mng_snooper = NULL;
}