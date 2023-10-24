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

#include "bpf.h"
#include "container.h"
#include "probe_mng.h"
#include "pod_mng.h"

#include "ipc.h"
#include "snooper.h"
#include "snooper.skel.h"
#include "snooper_bpf.h"

// Snooper obj name define
#define SNOOPER_OBJNAME_PROCID      "proc_id"
#define SNOOPER_OBJNAME_PROCNAME    "proc_name"
#define SNOOPER_OBJNAME_PODID       "pod_id"
#define SNOOPER_OBJNAME_CONTAINERID "container_id"
#define SNOOPER_OBJNAME_GAUSSDB     "gaussdb"
#define SNOOPER_OBJNAME_CUSTOM_LABELS "custom_labels"
#define SNOOPER_OBJNAME_POD_LABELS  "pod_labels"

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


static void refresh_snooper_obj(struct probe_s *probe);

void get_probemng_lock(void);
void put_probemng_lock(void);

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

    (void)snprintf(snooper_conf->conf.app.comm, sizeof(snooper_conf->conf.app.comm), "%s", comm);
    if (cmdline && cmdline[0] != 0) {
        snooper_conf->conf.app.cmdline = strdup(cmdline);
    }
    if (dbgdir && dbgdir[0] != 0) {
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

static int add_snooper_conf_pod(struct probe_s *probe, const char* pod_id)
{
    if (probe->snooper_conf_num >= SNOOPER_MAX) {
        return -1;
    }
    if (pod_id[0] == 0) {
        return 0;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }

    (void)snprintf(snooper_conf->conf.pod_id, sizeof(snooper_conf->conf.pod_id), "%s", pod_id);
    snooper_conf->type = SNOOPER_CONF_POD_ID;

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

    (void)snprintf(snooper_conf->conf.container_id, sizeof(snooper_conf->conf.container_id), "%s", container_id);
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

static void print_snooper_procid(struct probe_s *probe, void *json)
{
    void *procid_item;
    struct snooper_conf_s *snooper_conf;

    procid_item = Json_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_PROC_ID) {
            continue;
        }

        Json_AddUIntItemToArray(procid_item, snooper_conf->conf.proc_id);
    }
    Json_AddItemToObject(json, SNOOPER_OBJNAME_PROCID, procid_item);
    Json_Delete(procid_item);
}

static int parse_snooper_procid(struct probe_s *probe, const void *json)
{
    int ret;
    void *procid_item, *object;

    procid_item = Json_GetObjectItem(json, SNOOPER_OBJNAME_PROCID);
    if (procid_item == NULL) {
        return 0;
    }

    size_t size = Json_GetArraySize(procid_item);
    for (int i = 0; i < size; i++) {
        object = Json_GetArrayItem(procid_item, i);
        if (!Json_IsNumeric(object)) {
            return -1;
        }

	int valueInt = Json_GetValueInt(object);
	if (valueInt == INVALID_INT_NUM) {
	    return -1;
	}
        ret = add_snooper_conf_procid(probe, (u32)valueInt);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static struct custom_label_elem *dup_custom_labels_from_json(const void *labelItems, int num)
{
    struct custom_label_elem *custom_labels;
    void *labelItem;
    char *labelVal;
    char *keyValue;

    custom_labels = (struct custom_label_elem *)calloc(num, sizeof(struct custom_label_elem));
    if (!custom_labels) {
        return NULL;
    }

    struct key_value_pairs *kv_pairs = Json_GetKeyValuePairs(labelItems);
    if (!kv_pairs) {
        return NULL;
    }
    struct key_value *kv;

    int elemIdx = 0;
    Json_ArrayForEach(kv, kv_pairs) {
        labelVal = (char *)Json_GetValueString(kv->valuePtr);
        if (!labelVal) {
            free_custom_labels(custom_labels, num);
            return NULL;
        }
        custom_labels[elemIdx].key = strdup(kv->key);
        custom_labels[elemIdx].val = strdup(labelVal);
        if (!custom_labels[elemIdx].key || !custom_labels[elemIdx].val) {
            free_custom_labels(custom_labels, num);
            return NULL;
        }
        ++elemIdx;
    }
    Json_DeleteKeyValuePairs(kv_pairs);
    return custom_labels;
}

static int parse_snooper_custom_labels(struct probe_s *probe, const void *json)
{
    int ret;
    void *labelItems;
    int custom_label_num;
    struct custom_label_elem *custom_labels;

    labelItems = Json_GetObjectItem(json, SNOOPER_OBJNAME_CUSTOM_LABELS);
    if (!labelItems) {
        return 0;
    }
    if (!Json_IsObject(labelItems)) {
        return -1;
    }

    custom_label_num = (int)Json_GetArraySize(labelItems);
    if (custom_label_num == 0) {
        return 0;
    }
    custom_labels = dup_custom_labels_from_json(labelItems, custom_label_num);
    if (!custom_labels) {
        return -1;
    }
    update_custom_labels_locked(&probe->ext_label_conf, custom_labels, custom_label_num);

    return 0;
}

static struct pod_label_elem *dup_pod_labels_from_json(const void *labelItems, int num)
{
    struct pod_label_elem *pod_labels;
    char *labelKey;

    pod_labels = (struct pod_label_elem *)calloc(num, sizeof(struct pod_label_elem));
    if (!pod_labels) {
        return NULL;
    }

    struct key_value_pairs *kv_pairs = Json_GetKeyValuePairs(labelItems);
    if (!kv_pairs) {
        return NULL;
    }
    struct key_value *kv;
    int elemIdx = 0;
    Json_ArrayForEach(kv, kv_pairs) {
        labelKey = (char *)Json_GetValueString(kv->valuePtr);
        if (!labelKey) {
            free_pod_labels(pod_labels, num);
            return NULL;
        }
        pod_labels[elemIdx].key = strdup(labelKey);
        if (!pod_labels[elemIdx].key) {
            free_pod_labels(pod_labels, num);
            return NULL;
        }
        ++elemIdx;
    }
    Json_DeleteKeyValuePairs(kv_pairs);
    return pod_labels;
}

static int parse_snooper_pod_labels(struct probe_s *probe, const void *json)
{
    int ret;
    void *labelItems;
    int pod_label_num;
    struct pod_label_elem *pod_labels;

    labelItems = Json_GetObjectItem(json, SNOOPER_OBJNAME_POD_LABELS);
    if (!labelItems) {
        return 0;
    }
    if (!Json_IsArray(labelItems)) {
        return -1;
    }

    pod_label_num = (int)Json_GetArraySize(labelItems);
    if (pod_label_num == 0) {
        return 0;
    }
    pod_labels = dup_pod_labels_from_json(labelItems, pod_label_num);
    if (!pod_labels) {
        return -1;
    }
    update_pod_labels_locked(&probe->ext_label_conf, pod_labels, pod_label_num);

    return 0;
}

static void print_snooper_procname(struct probe_s *probe, void *json)
{
    void *procname_item, *object;
    struct snooper_conf_s *snooper_conf;

    procname_item = Json_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_APP) {
            continue;
        }

        object = Json_CreateObject();
        Json_AddStringToObject(object, SNOOPER_OBJNAME_COMM, snooper_conf->conf.app.comm);
        Json_AddStringToObject(object, SNOOPER_OBJNAME_CMDLINE, snooper_conf->conf.app.cmdline?:"");
        Json_AddStringToObject(object, SNOOPER_OBJNAME_DBGDIR, snooper_conf->conf.app.debuging_dir?:"");
        Json_AddItemToArray(procname_item, object);
        Json_Delete(object);
    }
    Json_AddItemToObject(json, SNOOPER_OBJNAME_PROCNAME, procname_item);
    Json_Delete(procname_item);
}

static int parse_snooper_procname(struct probe_s *probe, const void *json)
{
    int ret;
    void *procname_item, *comm_item, *cmdline_item, *dbgdir_item, *object;
    char *comm, *cmdline, *dbgdir;

    procname_item = Json_GetObjectItem(json, SNOOPER_OBJNAME_PROCNAME);
    if (procname_item == NULL) {
        return 0;
    }

    size_t size = Json_GetArraySize(procname_item);
    for (int i = 0; i < size; i++) {
        object = Json_GetArrayItem(procname_item, i);

        comm_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_COMM);
        cmdline_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_CMDLINE);
        dbgdir_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_DBGDIR);

        if ((comm_item == NULL) || (!Json_IsString(comm_item))) {
            return -1;
        }

        if (cmdline_item && (!Json_IsString(cmdline_item))) {
            return -1;
        }

        if (dbgdir_item && (!Json_IsString(dbgdir_item))) {
            return -1;
        }
        comm = (char *)Json_GetValueString(comm_item);
        cmdline = (cmdline_item != NULL) ? (char *)Json_GetValueString(cmdline_item) : NULL;
        dbgdir = (dbgdir_item != NULL) ? (char *)Json_GetValueString(dbgdir_item) : NULL;
        ret = add_snooper_conf_procname(probe, (const char *)comm, (const char *)cmdline, (const char *)dbgdir);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}


static void print_snooper_pod_container(struct probe_s *probe, void *json)
{
    void *pod_item, *cntr_item;
    struct snooper_conf_s *snooper_conf;

    pod_item = Json_CreateArray();
    cntr_item = Json_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type == SNOOPER_CONF_POD_ID) {
            Json_AddStringItemToArray(pod_item, snooper_conf->conf.pod_id);
            continue;
        }

        if (snooper_conf->type == SNOOPER_CONF_CONTAINER_ID) {
            Json_AddStringItemToArray(cntr_item,snooper_conf->conf.container_id);
            continue;
        }
    }
    Json_AddItemToObject(json, SNOOPER_OBJNAME_PODID, pod_item);
    Json_Delete(pod_item);
    Json_AddItemToObject(json, SNOOPER_OBJNAME_CONTAINERID, cntr_item);
    Json_Delete(cntr_item);
}

static int parse_snooper_pod_container(struct probe_s *probe, const void *json, const char *item_name)
{
    int ret;
    void *item, *object;
    int pod_flag = 0;

    if (!strcasecmp(item_name, SNOOPER_OBJNAME_PODID)) {
        pod_flag = 1;
    }

    item = Json_GetObjectItem(json, item_name);
    if (item == NULL) {
        return 0;
    }

    size_t size = Json_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        object = Json_GetArrayItem(item, i);
        if (!Json_IsString(object)) {
            return -1;
        }
        if (pod_flag) {
            ret = add_snooper_conf_pod(probe, (const char *)Json_GetValueString(object));
        } else {
            ret = add_snooper_conf_container(probe, (const char *)Json_GetValueString(object));
        }
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

static void print_snooper_gaussdb(struct probe_s *probe, void *json)
{
    void *gaussdb_item, *object;
    struct snooper_conf_s *snooper_conf;

    gaussdb_item = Json_CreateArray();
    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_GAUSSDB) {
            continue;
        }

        object = Json_CreateObject();
        Json_AddStringToObject(object, SNOOPER_OBJNAME_DBIP, snooper_conf->conf.gaussdb.ip?:"");
        Json_AddUIntItemToObject(object, SNOOPER_OBJNAME_DBPORT, snooper_conf->conf.gaussdb.port);
        Json_AddStringToObject(object, SNOOPER_OBJNAME_DBNAME, snooper_conf->conf.gaussdb.dbname?:"");
        Json_AddStringToObject(object, SNOOPER_OBJNAME_DBUSER, snooper_conf->conf.gaussdb.usr?:"");
        Json_AddStringToObject(object, SNOOPER_OBJNAME_DBPASS, snooper_conf->conf.gaussdb.pass?:"");
        Json_AddItemToArray(gaussdb_item, object);
        Json_Delete(object);
    }
    Json_AddItemToObject(json, SNOOPER_OBJNAME_GAUSSDB, gaussdb_item);
    Json_Delete(gaussdb_item);
}

static int parse_snooper_gaussdb(struct probe_s *probe, const void *json)
{
    int ret;
    void *gaussdb_item, *ip_item, *dbname_item, *usr_item, *pass_item, *port_item, *object;
    char *ip, *dbname, *usr, *pass;

    gaussdb_item = Json_GetObjectItem(json, SNOOPER_OBJNAME_GAUSSDB);
    if (gaussdb_item == NULL) {
        return 0;
    }

    size_t size = Json_GetArraySize(gaussdb_item);
    for (int i = 0; i < size; i++) {
        object = Json_GetArrayItem(gaussdb_item, i);

        ip_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_DBIP);
        dbname_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_DBNAME);
        usr_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_DBUSER);
        pass_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_DBPASS);
        port_item = Json_GetObjectItem(object, SNOOPER_OBJNAME_DBPORT);

        if ((ip_item == NULL) || (!Json_IsString(ip_item))) {
            return -1;
        }
        if ((dbname_item == NULL) || (!Json_IsString(dbname_item))) {
            return -1;
        }
        if ((usr_item == NULL) || (!Json_IsString(usr_item))) {
            return -1;
        }
        if ((pass_item == NULL) || (!Json_IsString(pass_item))) {
            return -1;
        }
        if ((port_item == NULL) || (!Json_IsNumeric(port_item))) {
            return -1;
        }

        ip = (char *)Json_GetValueString(ip_item);
        dbname = (char *)Json_GetValueString(dbname_item);
        usr = (char *)Json_GetValueString(usr_item);
        pass = (char *)Json_GetValueString(pass_item);
	int valueInt = Json_GetValueInt(port_item);
	if (valueInt == INVALID_INT_NUM) {
	    return -1;
	}
        ret = add_snooper_conf_gaussdb(probe, ip, dbname, usr, pass, (u32)valueInt);
        if (ret != 0) {
            return -1;
        }
    }

    return 0;
}

void print_snooper(struct probe_s *probe, void *json)
{
    print_snooper_procid(probe, json);
    print_snooper_procname(probe, json);
    print_snooper_pod_container(probe, json);
    print_snooper_gaussdb(probe, json);
}

static void __build_ipc_body(struct probe_s *probe, struct ipc_body_s* ipc_body)
{
    ipc_body->snooper_obj_num = 0;
    ipc_body->probe_flags = 0;

    for (int i = 0; i < SNOOPER_MAX; i++) {
        if (probe->snooper_objs[i] == NULL) {
            continue;
        }

        memcpy(&(ipc_body->snooper_objs[ipc_body->snooper_obj_num]),
                probe->snooper_objs[i], sizeof(struct snooper_obj_s));

        ipc_body->snooper_obj_num++;
    }

    ipc_body->probe_range_flags = probe->probe_range_flags;
    if (probe->is_params_chg) {
        ipc_body->probe_flags |= IPC_FLAGS_PARAMS_CHG;
    }
    if (probe->is_snooper_chg) {
        ipc_body->probe_flags |= IPC_FLAGS_SNOOPER_CHG;
    }
    memcpy(&(ipc_body->probe_param), &probe->probe_param, sizeof(struct probe_params));
    return;
}

int send_snooper_obj(struct probe_s *probe)
{
    struct ipc_body_s ipc_body; // Initialized at '__build_ipc_body' function

    // To prevent ipc queue full, we only send ipc msg to running probes.
    // However, the "RUNNING" flag may not be set by probe->cb thread when we get here in starting,
    // so take probe->resnd_snooper_for_restart into consideration as well.
    if (!probe || (!IS_RUNNING_PROBE(probe) && !probe->resnd_snooper_for_restart)) {
        return 0;
    }

    __build_ipc_body(probe, &ipc_body);
    return send_ipc_msg(__probe_mng_snooper->msq_id, (long)probe->probe_type, &ipc_body);
}

int parse_snooper(struct probe_s *probe, const void *json)
{
    int i;

    /* free current snooper config */
    for (i = 0 ; i < probe->snooper_conf_num ; i++) {
        free_snooper_conf(probe->snooper_confs[i]);
        probe->snooper_confs[i] = NULL;
    }
    probe->snooper_conf_num = 0;
    if (parse_snooper_procid(probe, json)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_PROCID);
        return -1;
    }

    if (parse_snooper_procname(probe, json)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_PROCNAME);
        return -1;
    }

    if (parse_snooper_pod_container(probe, json, SNOOPER_OBJNAME_PODID)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_PODID);
        return -1;
    }

    if (parse_snooper_pod_container(probe, json, SNOOPER_OBJNAME_CONTAINERID)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_CONTAINERID);
        return -1;
    }

    if (parse_snooper_gaussdb(probe, json)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_GAUSSDB);
        return -1;
    }

    if (parse_snooper_custom_labels(probe, json)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_CUSTOM_LABELS);
        return -1;
    }

    if (parse_snooper_pod_labels(probe, json)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_POD_LABELS);
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
        } else if ((unsigned char)cmdline[index] == (unsigned char)EOF) {
            cmdline[index] = '\0';
        }
        index++;
    }

    cmdline[index] = 0;

    (void)fclose(f);
    return 0;
}

#define PROC_STAT_CMD  "cat /proc/%s/stat 2>/dev/null"
static int __need_to_add_proc(const char *pid)
{
    char cmd[LINE_BUF_LEN];
    char line[LINE_BUF_LEN];
    cmd[0] = 0;
    line[0] = 0;

    (void)snprintf(cmd, LINE_BUF_LEN, PROC_STAT_CMD, pid);
    if (exec_cmd(cmd, line, LINE_BUF_LEN) != 0) {
        return 0;
    }

    cmd[0] = 0;
    (void)snprintf(cmd, LINE_BUF_LEN, "%u", getpid());
    if (strstr(line, cmd) != NULL) {
        return 0;
    }

    return 1;
}

static int __chk_cmdline_matched(const char *cmdline, const char *pid)
{
    int ret;
    char buf[__PROC_CMDLINE_MAX];

    if (cmdline == NULL) {
        return 0;
    }

    buf[0] = 0;
    ret = __read_proc_cmdline(pid, buf, __PROC_CMDLINE_MAX);
    if (ret) {
        return -1;
    }

    if (strstr(buf, cmdline) == NULL) {
        return -1;
    }

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
    if (con_info == NULL) {
        return -1;
    }

    int pos = __get_snooper_obj_idle(probe, SNOOPER_MAX);
    if (pos < 0) {
        return -1;
    }

    struct snooper_obj_s* snooper_obj = new_snooper_obj();
    if (snooper_obj == NULL) {
        return -1;
    }
    DEBUG("[SNOOPER] Adding container %s to snooper obj\n", con_info->con_id ?:"unknown");
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

static int gen_snooper_by_procname(struct probe_s *probe)
{
    int ret;
    int cmdline_obtained = 0;
    DIR *dir = NULL;
    struct dirent *entry;
    struct snooper_conf_s * snooper_conf;
    char comm[__PROC_NAME_MAX];
    char cmdline[__PROC_CMDLINE_MAX];

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

        for (int i = 0; i < probe->snooper_conf_num; i++) {
            snooper_conf = probe->snooper_confs[i];
            if (snooper_conf->type != SNOOPER_CONF_APP) {
                continue;
            }
            if (!__chk_snooper_pattern((const char *)snooper_conf->conf.app.comm, (const char *)comm)) {
                // 'comm' Unmatched
                continue;
            }

            if (!__need_to_add_proc(entry->d_name)) {
                continue;
            }

            if (snooper_conf->conf.app.cmdline) {
                if (!cmdline_obtained) {
                    cmdline[0] = 0;
                    ret = __read_proc_cmdline(entry->d_name, cmdline, __PROC_CMDLINE_MAX);
                    if (ret) {
                        break;
                    }
                    cmdline_obtained = 1;
                }

                if (strstr(cmdline, snooper_conf->conf.app.cmdline) == NULL) {
                    // 'cmdline' Unmatched
                    continue;
                }
            }
            // Well matched
            (void)add_snooper_obj_procid(probe, (u32)atoi(entry->d_name));
            break;
        }
        cmdline_obtained = 0;
    } while (1);

    closedir(dir);
    return 0;
}

static int gen_snooper_by_procid(struct probe_s *probe)
{
    struct snooper_conf_s * snooper_conf;

    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_PROC_ID) {
            continue;
        }

        if (add_snooper_obj_procid(probe, snooper_conf->conf.proc_id)) {
            return -1;
        }
    }
    return 0;
}

static int __gen_snooper_by_container(struct probe_s *probe, con_id_element *con_id_list)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    con_id_element *con_info_elem, *tmp;

    dir = opendir(__SYS_PROC_DIR);
    if (dir == NULL) {
        return -1;
    }

    do {
        entry = readdir(dir);
        if (entry == NULL) {
            break;
        }
        if (!__is_proc_dir(entry->d_name)) {
            continue;
        }

        container_id[0] = 0;
        (void)get_container_id_by_pid_cpuset((const char *)(entry->d_name), container_id, CONTAINER_ABBR_ID_LEN + 1);
        if (container_id[0] == 0) {
            continue;
        }

        LL_FOREACH_SAFE(con_id_list, con_info_elem, tmp) {
            if (strcmp((const char *)container_id, con_info_elem->con_id) == 0) {
                // Well matched
                (void)add_snooper_obj_procid(probe, (u32)atoi(entry->d_name));
                break;
            }
        }
    } while (1);

    closedir(dir);
    return 0;
}


static int gen_snooper_by_container(struct probe_s *probe)
{
    struct snooper_conf_s * snooper_conf;
    struct con_info_s *con_info;
    con_id_element *con_id_list = NULL;

    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_CONTAINER_ID || snooper_conf->conf.container_id[0] == 0) {
            continue;
        }

        con_info = get_and_add_con_info(FAKE_POD_ID, snooper_conf->conf.container_id);
        if (con_info == NULL) {
            WARN("[SNOOPER] Fail to get info of container %s\n", snooper_conf->conf.container_id);
            continue;
        }
        if (append_con_id_list(&con_id_list, con_info)) {
            free_con_id_list(con_id_list);
            return -1;
        }
        (void)add_snooper_obj_con_info(probe, con_info);
    }

    if (con_id_list) {
        (void)__gen_snooper_by_container(probe, con_id_list);
    }
    free_con_id_list(con_id_list);
    return 0;
}

static int gen_snooper_by_pod(struct probe_s *probe)
{
    struct snooper_conf_s * snooper_conf;
    struct pod_info_s *pod_info;
    con_id_element *con_id_list = NULL;

    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_POD_ID || snooper_conf->conf.pod_id[0] == 0) {
            continue;
        }

        pod_info = get_and_add_pod_info(snooper_conf->conf.pod_id);
        if (pod_info == NULL) {
            WARN("[SNOOPER] Failed to get info of pod %s\n", snooper_conf->conf.pod_id);
            continue;
        }

        if (pod_info->con_head == NULL) {
            continue;
        }

        struct containers_hash_t *con, *tmp;
        if (H_COUNT(pod_info->con_head) > 0) {
            H_ITER(pod_info->con_head, con, tmp) {
                if (append_con_id_list(&con_id_list, &con->con_info)) {
                    free_con_id_list(con_id_list);
                    return -1;
                }
                (void)add_snooper_obj_con_info(probe, &con->con_info);
            }
        }
    }

    if (con_id_list) {
        (void)__gen_snooper_by_container(probe, con_id_list);
    }
    free_con_id_list(con_id_list);
    return 0;
}

static int gen_snooper_by_gaussdb(struct probe_s *probe)
{
    struct snooper_conf_s * snooper_conf;

    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_GAUSSDB) {
            continue;
        }

        if (add_snooper_obj_gaussdb(probe, &(snooper_conf->conf.gaussdb))) {
            return -1;
        }
    }

    return 0;
}

typedef int (*probe_snooper_generator)(struct probe_s *);
struct snooper_generator_s {
    enum snooper_conf_e type;
    probe_snooper_generator generator;
};
struct snooper_generator_s snooper_generators[] = {
    {SNOOPER_CONF_APP,           gen_snooper_by_procname   },
    {SNOOPER_CONF_GAUSSDB,       gen_snooper_by_gaussdb    },
    {SNOOPER_CONF_PROC_ID,       gen_snooper_by_procid     },
    {SNOOPER_CONF_POD_ID,        gen_snooper_by_pod        },
    {SNOOPER_CONF_CONTAINER_ID,  gen_snooper_by_container  }
};

/* Flush current snooper obj and re-generate */
static void refresh_snooper_obj(struct probe_s *probe)
{
    int i;
    struct snooper_conf_s * snooper_conf;
    struct snooper_generator_s *generator;
    size_t size = sizeof(snooper_generators) / sizeof(struct snooper_generator_s);

    for (i = 0 ; i < SNOOPER_MAX ; i++) {
        free_snooper_obj(probe->snooper_objs[i]);
        probe->snooper_objs[i] = NULL;
    }

    for (i = 0; i < size; i++) {
        generator = &(snooper_generators[i]);
        if (generator->generator(probe)) {
            return;
        }
    }
}

static char __rcv_snooper_proc_exec_sub(struct probe_s *probe, const char *comm, u32 proc_id,
                                        char *container_id, char *pod_id)
{
    char snooper_obj_added = 0;
    struct snooper_conf_s *snooper_conf;
    char pid_str[INT_LEN];

    for (int j = 0; j < probe->snooper_conf_num && j < SNOOPER_MAX; j++) {
        snooper_conf = probe->snooper_confs[j];
        if (snooper_conf && snooper_conf->type == SNOOPER_CONF_APP) {
            if (__chk_snooper_pattern((const char *)(snooper_conf->conf.app.comm), comm)) {
                pid_str[0] = 0;
                (void)snprintf(pid_str, sizeof(pid_str), "%d", proc_id);
                if (__chk_cmdline_matched((const char *)(snooper_conf->conf.app.cmdline), (const char *)pid_str) == 0 &&
                    __need_to_add_proc(pid_str)) {
                    (void)add_snooper_obj_procid(probe, proc_id);
                    snooper_obj_added = 1;
                }
            }
        }
        if (snooper_conf && snooper_conf->type == SNOOPER_CONF_CONTAINER_ID) {
            if (container_id[0] != 0 && !strcasecmp(container_id, snooper_conf->conf.container_id)) {
                (void)add_snooper_obj_procid(probe, proc_id);
                snooper_obj_added = 1;
            }
        }
        if (snooper_conf && snooper_conf->type == SNOOPER_CONF_POD_ID) {
            if (pod_id[0] != 0 && !strcasecmp(pod_id, snooper_conf->conf.pod_id)) {
                (void)add_snooper_obj_procid(probe, proc_id);
                snooper_obj_added = 1;
            }
        }
    }
    return snooper_obj_added;
}

static void __rcv_snooper_proc_exec(struct probe_mng_s *probe_mng, const char* comm, u32 proc_id)
{
    int i;
    char pod_id_ready = 0;
    char snooper_obj_added;
    struct probe_s *probe;
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char pod_id[POD_ID_LEN + 1];
    char pid_str[INT_LEN + 1];

    pid_str[0] = 0;
    (void)snprintf(pid_str, INT_LEN + 1, "%u", proc_id);

    container_id[0] = 0;
    pod_id[0] = 0;
    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        probe = probe_mng->probes[i];
        if (!probe) {
            continue;
        }

        if (pod_id_ready == 0) {
            (void)get_container_id_by_pid_cpuset(pid_str, container_id, CONTAINER_ABBR_ID_LEN + 1);
            if (container_id[0] != 0) {
                (void)get_container_pod_id((const char *)container_id, pod_id, POD_ID_LEN + 1);
            }
            pod_id_ready = 1;
        }

        snooper_obj_added = __rcv_snooper_proc_exec_sub(probe, comm, proc_id, container_id, pod_id);

        if (snooper_obj_added) {
            probe->is_params_chg = 0;
            probe->is_snooper_chg = 1;
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
            probe->is_params_chg = 0;
            probe->is_snooper_chg = 1;
            (void)send_snooper_obj(probe);
        }
    }
}

static int rcv_snooper_proc_evt(void *ctx, void *data, __u32 size)
{
    struct snooper_proc_evt_s *evt = data;
    char comm[TASK_COMM_LEN];

    comm[0] = 0;
    char *p = strrchr(evt->filename, '/');
    if (p) {
        (void)snprintf(comm, sizeof(comm), "%s", p + 1);
    } else {
        (void)snprintf(comm, sizeof(comm), "%s", evt->filename);
    }

    get_probemng_lock();

    if (evt->proc_event == PROC_EXEC) {
        __rcv_snooper_proc_exec(__probe_mng_snooper, (const char *)comm, (u32)evt->pid);
    } else {
        __rcv_snooper_proc_exit(__probe_mng_snooper, (u32)evt->pid);
    }
    put_probemng_lock();
    return 0;
}

static char __rcv_snooper_cgrp_exec_sub(struct probe_s *probe, struct con_info_s *con_info)
{
    char snooper_obj_added = 0;
    struct snooper_conf_s *snooper_conf;

    for (int j = 0; j < probe->snooper_conf_num && j < SNOOPER_MAX; j++) {
        snooper_conf = probe->snooper_confs[j];
        if (!snooper_conf) {
            continue;
        }
        if (snooper_conf->type == SNOOPER_CONF_POD_ID) {
            if (con_info->pod_info_ptr->pod_id[0] != 0 &&
                !strcasecmp(con_info->pod_info_ptr->pod_id, snooper_conf->conf.pod_id)) {
                add_snooper_obj_con_info(probe, con_info);
                snooper_obj_added = 1;
            }
        } else if (snooper_conf->type == SNOOPER_CONF_CONTAINER_ID) {
            if (con_info->con_id[0] != 0 && !strcasecmp(con_info->con_id, snooper_conf->conf.container_id)) {
                add_snooper_obj_con_info(probe, con_info);
                snooper_obj_added = 1;
            }
        }
    }
    return snooper_obj_added;
}

static void __rcv_snooper_cgrp_exec(struct probe_mng_s *probe_mng, char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    char snooper_obj_added;
    int i, j;
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

        snooper_obj_added = __rcv_snooper_cgrp_exec_sub(probe, con_info);

        if (snooper_obj_added) {
            probe->is_params_chg = 0;
            probe->is_snooper_chg = 1;
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
            probe->is_params_chg = 0;
            probe->is_snooper_chg = 1;
            (void)send_snooper_obj(probe);
        }
    }
}

static int rcv_snooper_cgrp_evt(void *ctx, void *data, __u32 size)
{
    struct snooper_cgrp_evt_s *msg_data = (struct snooper_cgrp_evt_s *)data;

    char pod_id[POD_ID_LEN + 1] = {0};
    char con_id[CONTAINER_ABBR_ID_LEN + 1] = {0};
    enum id_ret_t id_ret = get_pod_container_id(msg_data->cgrp_path, pod_id, con_id);

    if (id_ret == ID_FAILED) {
        return 0;
    }

    if (msg_data->cgrp_event == CGRP_MK) {
        add_pod_con_map(pod_id, con_id, id_ret);
        if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
            get_probemng_lock();
            __rcv_snooper_cgrp_exec(__probe_mng_snooper, pod_id, con_id, id_ret);
            put_probemng_lock();
        }
    } else {
        del_pod_con_map(pod_id, con_id, id_ret);
        if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
            get_probemng_lock();
            __rcv_snooper_cgrp_exit(__probe_mng_snooper, pod_id, con_id, id_ret);
            put_probemng_lock();
        }
    }

    return 0;
}

static void loss_data(void *ctx, int cpu, u64 cnt)
{
    // TODO: debuging
}

int load_snooper_bpf(struct probe_mng_s *probe_mng)
{
    int ret = 0;
    struct snooper_bpf *snooper_skel;
    struct bpf_buffer *buffer = NULL;
    int kern_ver = probe_kernel_version();

    LIBBPF_OPTS(bpf_object_open_opts, opts);
    ensure_core_btf(&opts);

    __probe_mng_snooper = probe_mng;

    INIT_BPF_APP(snooper, EBPF_RLIM_LIMITED);

    /* Open load and verify BPF application */
    snooper_skel = snooper_bpf__open_opts(&opts);
    if (!snooper_skel) {
        ret = -1;
        ERROR("Failed to open BPF snooper_skel.\n");
        goto end;
    }

    int attach_tracepoint = (kern_ver > KERNEL_VERSION(4, 18, 0));
    PROG_ENABLE_ONLY_IF(snooper, bpf_raw_trace_sched_process_fork, attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_raw_trace_sched_process_exec, attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_raw_trace_sched_process_exit, attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_raw_trace_cgroup_mkdir, attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_raw_trace_cgroup_rmdir, attach_tracepoint);

    PROG_ENABLE_ONLY_IF(snooper, bpf_wake_up_new_task, !attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_trace_sched_process_fork_func, !attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_trace_sched_process_exec_func, !attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_trace_sched_process_exit_func, !attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_trace_cgroup_mkdir_func, !attach_tracepoint);
    PROG_ENABLE_ONLY_IF(snooper, bpf_trace_cgroup_rmdir_func, !attach_tracepoint);

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

    buffer = bpf_buffer__new(snooper_skel->maps.snooper_proc_channel, snooper_skel->maps.heap);
    if (buffer == NULL) {
        goto end;
    }
    ret = bpf_buffer__open(buffer, rcv_snooper_proc_evt, loss_data, NULL);
    if (ret) {
        ERROR("[SNOOPER] Open 'snooper_proc_channel' bpf_buffer failed.\n");
        bpf_buffer__free(buffer);
        goto end;
    }

    probe_mng->snooper_proc_pb = buffer;

    buffer = bpf_buffer__new(snooper_skel->maps.snooper_cgrp_channel, snooper_skel->maps.heap);
    if (buffer == NULL) {
        ret = -1;
        goto end;
    }
    ret = bpf_buffer__open(buffer, rcv_snooper_cgrp_evt, loss_data, NULL);
    if (ret) {
        ERROR("[SNOOPER] Open 'snooper_cgrp_channel' bpf_buffer failed.\n");
        bpf_buffer__free(buffer);
        goto end;
    }
    probe_mng->snooper_cgrp_pb = buffer;

    probe_mng->snooper_skel = snooper_skel;
    probe_mng->btf_custom_path = opts.btf_custom_path;

    return 0;

end:
    if (snooper_skel) {
        snooper_bpf__destroy(snooper_skel);
        probe_mng->snooper_skel = NULL;
    }

    cleanup_core_btf(&opts);

    if (probe_mng->snooper_proc_pb) {
        bpf_buffer__free((struct bpf_buffer *)probe_mng->snooper_proc_pb);
        probe_mng->snooper_proc_pb = NULL;
    }
    if (probe_mng->snooper_cgrp_pb) {
        bpf_buffer__free((struct bpf_buffer *)probe_mng->snooper_cgrp_pb);
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

    if (probe_mng->btf_custom_path) {
        free((char *)probe_mng->btf_custom_path);
        probe_mng->btf_custom_path = NULL;
    }

    if (probe_mng->snooper_proc_pb) {
        bpf_buffer__free((struct bpf_buffer *)probe_mng->snooper_proc_pb);
        probe_mng->snooper_proc_pb = NULL;
    }
    if (probe_mng->snooper_cgrp_pb) {
        bpf_buffer__free((struct bpf_buffer *)probe_mng->snooper_cgrp_pb);
        probe_mng->snooper_cgrp_pb = NULL;
    }
    __probe_mng_snooper = NULL;
}
