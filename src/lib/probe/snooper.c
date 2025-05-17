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
#include "json_tool.h"

#include "ipc.h"
#include "snooper.skel.h"
#include "snooper_bpf.h"
#include "snooper.h"

// Snooper obj name define
#define SNOOPER_OBJNAME_PROCID      "proc_id"
#define SNOOPER_OBJNAME_PROCNAME    "proc_name"
#define SNOOPER_OBJNAME_PODID       "pod_id"
#define SNOOPER_OBJNAME_CONTAINERID "container_id"
#define SNOOPER_OBJNAME_CONTAINERNAME    "container_name"
#define SNOOPER_OBJNAME_CUSTOM_LABELS "custom_labels"
#define SNOOPER_OBJNAME_POD_LABELS  "pod_labels"

#define CUSTOM_LABELS_MAX_NUM        10
#define POD_LABELS_MAX_NUM           10
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
    if (probe->snooper_conf_num >= SNOOPER_CONF_MAX) {
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
    if (probe->snooper_conf_num >= SNOOPER_CONF_MAX) {
        return -1;
    }

    if (comm == NULL || comm[0] == 0) {
        return 0;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }

    (void)snprintf(snooper_conf->conf.app.comm, sizeof(snooper_conf->conf.app.comm), "%s", comm);
    if (cmdline && cmdline[0] != 0) {
        snooper_conf->conf.app.cmdline = strdup(cmdline);
        if (!snooper_conf->conf.app.cmdline) {
            free_snooper_conf(snooper_conf);
            return -1;
        }
    }
    if (dbgdir && dbgdir[0] != 0) {
        snooper_conf->conf.app.debuging_dir = strdup(dbgdir);
        if (!snooper_conf->conf.app.debuging_dir) {
            free_snooper_conf(snooper_conf);
            return -1;
        }
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
    if (probe->snooper_conf_num >= SNOOPER_CONF_MAX) {
        return -1;
    }
    if (pod_id == NULL || pod_id[0] == 0) {
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
    if (probe->snooper_conf_num >= SNOOPER_CONF_MAX) {
        return -1;
    }

    if (container_id == NULL || container_id[0] == 0) {
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

static int add_snooper_conf_container_name(struct probe_s *probe, const char* container_name)
{
    if (probe->snooper_conf_num >= SNOOPER_MAX) {
        return -1;
    }

    if (container_name == NULL) {
        return 0;
    }

    if (check_path_for_security(container_name)) {
        return -1;
    }

    struct snooper_conf_s* snooper_conf = new_snooper_conf();
    if (snooper_conf == NULL) {
        return -1;
    }

    (void)snprintf(snooper_conf->conf.container_name,
        sizeof(snooper_conf->conf.container_name), "%s", container_name);
    snooper_conf->type = SNOOPER_CONF_CONTAINER_NAME;

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
    for (size_t i = 0; i < size; i++) {
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
    char *labelVal;

    custom_labels = (struct custom_label_elem *)calloc(num, sizeof(struct custom_label_elem));
    if (!custom_labels) {
        return NULL;
    }

    struct key_value_pairs *kv_pairs = Json_GetKeyValuePairs(labelItems);
    if (!kv_pairs) {
        free_custom_labels(custom_labels, num);
        return NULL;
    }
    struct key_value *kv;

    int elemIdx = 0;
    Json_ArrayForEach(kv, kv_pairs) {
        labelVal = (char *)Json_GetValueString(kv->valuePtr);
        if (!labelVal) {
            Json_DeleteKeyValuePairs(kv_pairs);
            free_custom_labels(custom_labels, num);
            return NULL;
        }
        custom_labels[elemIdx].key = strdup(kv->key);
        custom_labels[elemIdx].val = strdup(labelVal);
        if (!custom_labels[elemIdx].key || !custom_labels[elemIdx].val) {
            Json_DeleteKeyValuePairs(kv_pairs);
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
    if (custom_label_num > CUSTOM_LABELS_MAX_NUM) {
        return -1;
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
        free_pod_labels(pod_labels, num);
        return NULL;
    }
    struct key_value *kv;
    int elemIdx = 0;
    Json_ArrayForEach(kv, kv_pairs) {
        labelKey = (char *)Json_GetValueString(kv->valuePtr);
        if (!labelKey) {
            Json_DeleteKeyValuePairs(kv_pairs);
            free_pod_labels(pod_labels, num);
            return NULL;
        }
        pod_labels[elemIdx].key = strdup(labelKey);
        if (!pod_labels[elemIdx].key) {
            Json_DeleteKeyValuePairs(kv_pairs);
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
    if (pod_label_num > POD_LABELS_MAX_NUM) {
        return -1;
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
    for (size_t i = 0; i < size; i++) {
        object = Json_GetArrayItem(procname_item, i);
        if (!Json_IsObject(object)) {
            return -1;
        }

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
    void *pod_item, *cntr_item, *cntrname_item;
    struct snooper_conf_s *snooper_conf;

    pod_item = Json_CreateArray();
    cntr_item = Json_CreateArray();
    cntrname_item = Json_CreateArray();
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

        if (snooper_conf->type == SNOOPER_CONF_CONTAINER_NAME) {
            Json_AddStringItemToArray(cntrname_item,snooper_conf->conf.container_name);
            continue;
        }
    }
    Json_AddItemToObject(json, SNOOPER_OBJNAME_PODID, pod_item);
    Json_Delete(pod_item);
    Json_AddItemToObject(json, SNOOPER_OBJNAME_CONTAINERID, cntr_item);
    Json_Delete(cntr_item);
    Json_AddItemToObject(json, SNOOPER_OBJNAME_CONTAINERNAME, cntrname_item);
    Json_Delete(cntrname_item);
}

static int parse_snooper_pod_container(struct probe_s *probe, const void *json, const char *item_name)
{
    int ret;
    void *item, *object;
    enum snooper_conf_e conf_flag = SNOOPER_CONF_CONTAINER_ID;

    if (!strcasecmp(item_name, SNOOPER_OBJNAME_CONTAINERNAME)) {
        conf_flag = SNOOPER_CONF_CONTAINER_NAME;
    } else if (!strcasecmp(item_name, SNOOPER_OBJNAME_PODID)) {
        conf_flag = SNOOPER_CONF_POD_ID;
    }

    item = Json_GetObjectItem(json, item_name);
    if (item == NULL) {
        return 0;
    }

    size_t size = Json_GetArraySize(item);
    for (size_t i = 0; i < size; i++) {
        object = Json_GetArrayItem(item, i);
        if (!Json_IsString(object)) {
            return -1;
        }
        switch (conf_flag) {
            case SNOOPER_CONF_CONTAINER_NAME:
                ret = add_snooper_conf_container_name(probe, (const char *)Json_GetValueString(object));
                break;
            case SNOOPER_CONF_POD_ID:
                ret = add_snooper_conf_pod(probe, (const char *)Json_GetValueString(object));
                break;
            case SNOOPER_CONF_CONTAINER_ID:
                ret = add_snooper_conf_container(probe, (const char *)Json_GetValueString(object));
                break;
            default:
                break;
        }
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
}

static void __build_ipc_body(struct probe_s *probe, struct ipc_body_s* ipc_body)
{
    ipc_body->snooper_obj_num = 0;
    ipc_body->probe_flags = 0;
    u8 snooper_type = probe->snooper_type;

    for (int i = 0; i < SNOOPER_MAX; i++) {
        if (probe->snooper_objs[i] == NULL || probe->snooper_objs[i]->type == SNOOPER_OBJ_MAX) {
            continue;
        }

        if (probe->snooper_objs[i]->type == SNOOPER_OBJ_PROC &&
            (snooper_type & SNOOPER_TYPE_PROC) == 0) {
            continue;
        }

        if (probe->snooper_objs[i]->type == SNOOPER_OBJ_CON &&
            (snooper_type & SNOOPER_TYPE_CON) == 0) {
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
    if (probe->resnd_snooper_for_restart) {
        ipc_body->probe_flags = (IPC_FLAGS_SNOOPER_CHG | IPC_FLAGS_SNOOPER_CHG);
    }
    memcpy(&(ipc_body->probe_param), &probe->probe_param, sizeof(struct probe_params));
    return;
}


// To prevent ipc queue full, we only send ipc msg to running probes.
// However, the "RUNNING" flag may not be set by probe->cb thread when we get here in starting,
// so take probe->resnd_snooper_for_restart into consideration as well.
static inline int need_send_snooper_obj(struct probe_s *probe)
{
    if (!probe || (!IS_RUNNING_PROBE(probe) && !probe->resnd_snooper_for_restart)) {
        return 0;
    }

    return 1;
}

int send_snooper_obj(struct probe_s *probe)
{
    struct ipc_body_s ipc_body; // Initialized at '__build_ipc_body' function
    long probetype = 0;

    if (need_send_snooper_obj(probe) == 0) {
        return 0;
    }

    __build_ipc_body(probe, &ipc_body);
    if (probe->probe_type == PROBE_CUSTOM) {
        probetype = (long)(PROBE_CUSTOM_IPC + probe->custom.index);
        return send_custom_ipc_msg(__probe_mng_snooper->msq_id, probetype, &ipc_body, &(probe->custom.custom_ipc_msg));
    }

    probetype = (long)probe->probe_type;
    return send_ipc_msg(__probe_mng_snooper->msq_id, (long)probe->probe_type, &ipc_body);
}

int parse_snooper(struct probe_s *probe, const void *json)
{
    int i;

    if (probe->snooper_type == SNOOPER_TYPE_NONE) {
        return 0;
    }

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

    if (parse_snooper_pod_container(probe, json, SNOOPER_OBJNAME_CONTAINERNAME)) {
        PARSE_ERR("Error occurs when parsing snooper %s", SNOOPER_OBJNAME_CONTAINERNAME);
        return -1;
    }

    if (probe->snooper_conf_num == 0) {
        PARSE_ERR("the snooper for %s cannot be empty", probe->name);
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

    if (snooper_obj->type == SNOOPER_OBJ_CON) {
        if (snooper_obj->obj.con_info.con_id) {
            (void)free(snooper_obj->obj.con_info.con_id);
        }
        if (snooper_obj->obj.con_info.libc_path) {
            (void)free(snooper_obj->obj.con_info.libc_path);
        }
        if (snooper_obj->obj.con_info.libssl_path) {
            (void)free(snooper_obj->obj.con_info.libssl_path);
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
                    SNOOPER_CONF_MAX * (sizeof(struct snooper_conf_s *)));
    (void)memset(&probe->snooper_confs, 0, SNOOPER_CONF_MAX * (sizeof(struct snooper_conf_s *)));

    (void)memcpy(&probe_backup->snooper_objs, &probe->snooper_objs,
                    SNOOPER_MAX * (sizeof(struct snooper_obj_s *)));
    (void)memset(&probe->snooper_objs, 0, SNOOPER_MAX * (sizeof(struct snooper_obj_s *)));
}

void rollback_snooper(struct probe_s *probe, struct probe_s *probe_backup)
{
    int i;

    for (i = 0 ; i < SNOOPER_CONF_MAX; i++) {
        free_snooper_conf(probe->snooper_confs[i]);
        probe->snooper_confs[i] = probe_backup->snooper_confs[i];
        probe_backup->snooper_confs[i] = NULL;
    }

    for (i = 0 ; i < SNOOPER_MAX; i++) {
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
#define __PROC_CMDLINE_MAX          4096
static int __read_proc_comm(const char *dir_name, char *comm, size_t size)
{
    char proc_comm_path[PATH_LEN];
    FILE *f;

    proc_comm_path[0] = 0;
    (void)snprintf(proc_comm_path, sizeof(proc_comm_path), __SYS_PROC_COMM, dir_name);

    f = fopen(proc_comm_path, "r");
    if (f == NULL) {
        return -1;
    }

    if (fgets(comm, size, f) == NULL) {
        fclose(f);
        return -1;
    }

    char *p = strchr(comm, '\n');
    if (p) {
        *p = 0;
    }
    fclose(f);
    return 0;
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
            cmdline[size - 1] = '\0';
            break;
        }
        cmdline[index] = fgetc(f);
        if (cmdline[index] == '\"') {
            if (index > size - 2) {
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

#define PROC_STAT_PATH          "/proc/%s/stat"
static int __need_to_add_proc(const char *pid)
{
    char proc_stat_path[PATH_LEN];
    pid_t ppid;
    FILE *f;
    int ret;

    proc_stat_path[0] = 0;
    (void)snprintf(proc_stat_path, sizeof(proc_stat_path), PROC_STAT_PATH, pid);
    f = fopen(proc_stat_path, "r");
    if (f == NULL) {
        return 0;
    }

    /* /proc/pid/stat: pid comm task_state ppid ..., so skip first 3 fields */
    ret = fscanf(f, "%*s %*s %*s %d", &ppid);
    if (ret != 1 || ppid == getpid()) {
        fclose(f);
        return 0;
    }

    fclose(f);
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
    for (size_t i = 0; i < size; i++) {
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
    snooper_obj->obj.con_info.cpucg_inode = con_info->cpucg_inode;
    if (con_info->con_id[0]) {
        snooper_obj->obj.con_info.con_id = strdup(con_info->con_id);
        if (!snooper_obj->obj.con_info.con_id) {
            goto err;
        }
    }
    if (probe->probe_type == PROBE_SLI && (con_info->container_name[0])) {
        snooper_obj->obj.con_info.container_name = strdup(con_info->container_name);
        if (!snooper_obj->obj.con_info.container_name) {
            goto err;
        }
    }
    if (probe->probe_type == PROBE_PROC && (con_info->libc_path[0])) {
        snooper_obj->obj.con_info.libc_path = strdup(con_info->libc_path);
        if (!snooper_obj->obj.con_info.libc_path) {
            goto err;
        }
    }
    if (probe->probe_type == PROBE_L7 && (con_info->libssl_path[0])) {
        snooper_obj->obj.con_info.libssl_path = strdup(con_info->libssl_path);
        if (!snooper_obj->obj.con_info.libssl_path) {
            goto err;
        }
    }
    probe->snooper_objs[pos] = snooper_obj;
    return 0;

err:
    WARN("add_snooper_obj_con_info add snooper obj failed !\n");
    free_snooper_obj(snooper_obj);
    return -1;
}

static int gen_snooper_by_procname(struct probe_s *probe)
{
    int ret;
    int cmdline_obtained = 0;
    DIR *dir = NULL;
    struct dirent *entry;
    struct snooper_conf_s * snooper_conf;
    char comm[TASK_COMM_LEN];
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
        if (!__is_proc_dir(entry->d_name)) {
            continue;
        }

        comm[0] = 0;
        ret = __read_proc_comm(entry->d_name, comm, sizeof(comm));
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
            (void)add_snooper_obj_procid(probe, strtoul(entry->d_name, NULL, 10));
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
                (void)add_snooper_obj_procid(probe, strtoul(entry->d_name, NULL, 10));
                break;
            }
        }
    } while (1);

    closedir(dir);
    return 0;
}

static int gen_snooper_by_container_name(struct probe_s *probe)
{
    struct snooper_conf_s * snooper_conf;
    struct con_info_s *con_info;
    FILE *f;
    char cmd[COMMAND_LEN];
    char line[CONTAINER_ID_LEN];

    for (int i = 0; i < probe->snooper_conf_num; i++) {
        snooper_conf = probe->snooper_confs[i];
        if (snooper_conf->type != SNOOPER_CONF_CONTAINER_NAME) {
            continue;
        }

        cmd[0] = 0;
        (void)snprintf(cmd, COMMAND_LEN,
            "docker ps -q --filter \"name=%s\"", (const char *)snooper_conf->conf.container_name);
        f = popen_chroot(cmd, "r");
        if (f == NULL) {
            return -1;
        }
        while (!feof(f)) {
            (void)memset(line, 0, CONTAINER_ID_LEN);
            if (fgets(line, CONTAINER_ID_LEN, f) == NULL) {
                (void)pclose(f);
                return -1;
            }

            con_info = get_and_add_con_info(FAKE_POD_ID, line);
            if (con_info == NULL) {
                WARN("[SNOOPER] Fail to get info of container %s from container name %s\n",
                line,
                snooper_conf->conf.container_name);
                continue;
            }

            if (add_snooper_obj_con_info(probe, con_info) == -1) {
                WARN("[SNOOPER] Fail to add snooper to con info from container name %s\n",
                     con_info->con_id[0] == 0 ? "null" : con_info->con_id, snooper_conf->conf.container_name);
                continue;
            }
        }
        (void)pclose(f);
    }

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
        if (add_snooper_obj_con_info(probe, con_info) == -1) {
            WARN("[SNOOPER] Fail to add snooper to container info from container name %s\n",
                 con_info->con_id[0] == 0 ? "null" : con_info->con_id, snooper_conf->conf.container_name);
            continue;
        }
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
                if (add_snooper_obj_con_info(probe, &con->con_info) == -1) {
                    WARN("[SNOOPER] Fail to add snooper to pod info from container name %s\n",
                         con->con_info.con_id[0] == 0 ? "null" : con->con_info.con_id, snooper_conf->conf.container_name);
                    continue;
                }
            }
        }
    }

    if (con_id_list) {
        (void)__gen_snooper_by_container(probe, con_id_list);
    }
    free_con_id_list(con_id_list);
    return 0;
}

typedef int (*probe_snooper_generator)(struct probe_s *);
struct snooper_generator_s {
    enum snooper_conf_e type;
    probe_snooper_generator generator;
};
struct snooper_generator_s snooper_generators[] = {
    {SNOOPER_CONF_APP,           gen_snooper_by_procname   },
    {SNOOPER_CONF_PROC_ID,       gen_snooper_by_procid     },
    {SNOOPER_CONF_POD_ID,        gen_snooper_by_pod        },
    {SNOOPER_CONF_CONTAINER_ID,  gen_snooper_by_container  },
    {SNOOPER_CONF_CONTAINER_NAME,  gen_snooper_by_container_name  }
};

/* Flush current snooper obj and re-generate */
static void refresh_snooper_obj(struct probe_s *probe)
{
    int i;
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

    for (int j = 0; j < probe->snooper_conf_num && j < SNOOPER_CONF_MAX; j++) {
        snooper_conf = probe->snooper_confs[j];
        if (snooper_conf && snooper_conf->type == SNOOPER_CONF_APP) {
            if (__chk_snooper_pattern((const char *)(snooper_conf->conf.app.comm), comm)) {
                pid_str[0] = 0;
                (void)snprintf(pid_str, sizeof(pid_str), "%u", proc_id);
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
    struct ipc_body_s ipc_body;
    char container_id[CONTAINER_ABBR_ID_LEN + 1];
    char pod_id[POD_ID_LEN + 1];
    char pid_str[INT_LEN + 1];

    pid_str[0] = 0;
    (void)snprintf(pid_str, INT_LEN + 1, "%u", proc_id);

    container_id[0] = 0;
    pod_id[0] = 0;
    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        get_probemng_lock();
        probe = probe_mng->probes[i];
        if (!probe) {
            put_probemng_lock();
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
            if (need_send_snooper_obj(probe)) {
                __build_ipc_body(probe, &ipc_body);
                put_probemng_lock();
                (void)send_ipc_msg(__probe_mng_snooper->msq_id, (long)probe->probe_type, &ipc_body);
                continue;
            }
        }
        put_probemng_lock();
    }
}

static void __rcv_snooper_proc_exit(struct probe_mng_s *probe_mng, u32 proc_id)
{
    char snooper_obj_removed;
    int i, j;
    struct probe_s *probe;
    struct snooper_obj_s *snooper_obj;
    struct ipc_body_s ipc_body;

    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        get_probemng_lock();
        probe = probe_mng->probes[i];
        if (!probe || probe->snooper_type == SNOOPER_TYPE_NONE) {
            put_probemng_lock();
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
            if (need_send_snooper_obj(probe)) {
                __build_ipc_body(probe, &ipc_body);
                put_probemng_lock();
                (void)send_ipc_msg(__probe_mng_snooper->msq_id, (long)probe->probe_type, &ipc_body);
                continue;
            }
        }
        put_probemng_lock();
    }
}

static int rcv_snooper_proc_evt(void *ctx, void *data, __u32 size)
{
    struct snooper_proc_evt_s *evt = data;

    if (evt->proc_event == PROC_EXEC) {
        __rcv_snooper_proc_exec(__probe_mng_snooper, (const char *)evt->comm, (u32)evt->pid);
    } else {
        __rcv_snooper_proc_exit(__probe_mng_snooper, (u32)evt->pid);
    }
    return 0;
}

static char __rcv_snooper_cgrp_exec_sub(struct probe_s *probe, struct con_info_s *con_info)
{
    char snooper_obj_added = 0;
    struct snooper_conf_s *snooper_conf;

    for (int j = 0; j < probe->snooper_conf_num && j < SNOOPER_CONF_MAX; j++) {
        snooper_conf = probe->snooper_confs[j];
        if (!snooper_conf) {
            continue;
        }
        if (snooper_conf->type == SNOOPER_CONF_POD_ID) {
            if (con_info->pod_info_ptr->pod_id[0] != 0 &&
                !strcasecmp(con_info->pod_info_ptr->pod_id, snooper_conf->conf.pod_id)) {
                snooper_obj_added = add_snooper_obj_con_info(probe, con_info) == -1 ? 0 : 1;
            }
        } else if (snooper_conf->type == SNOOPER_CONF_CONTAINER_ID) {
            if (con_info->con_id[0] != 0 && !strcasecmp(con_info->con_id, snooper_conf->conf.container_id)) {
                snooper_obj_added = add_snooper_obj_con_info(probe, con_info) == -1 ? 0: 1;
            }
        } else if (snooper_conf->type == SNOOPER_CONF_CONTAINER_NAME) {
            if (strstr((const char *)con_info->container_name, (const char *)(snooper_conf->conf.container_name)) != NULL) {
                snooper_obj_added = add_snooper_obj_con_info(probe, con_info) == -1 ? 0 : 1;
            }
        }
    }
    return snooper_obj_added;
}

static void __rcv_snooper_cgrp_exec(struct probe_mng_s *probe_mng, char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    char snooper_obj_added;
    int i;
    struct probe_s *probe;
    struct ipc_body_s ipc_body;
    get_probemng_lock();
    struct con_info_s *con_info = get_con_info(pod_id, con_id);
    if (con_info == NULL || con_info->pod_info_ptr == NULL) {
        put_probemng_lock();
        return;
    }
    put_probemng_lock();

    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        get_probemng_lock();
        probe = probe_mng->probes[i];
        if (!probe) {
            put_probemng_lock();
            continue;
        }

        snooper_obj_added = __rcv_snooper_cgrp_exec_sub(probe, con_info);

        if (snooper_obj_added) {
            probe->is_params_chg = 0;
            probe->is_snooper_chg = 1;
            if (need_send_snooper_obj(probe)) {
                __build_ipc_body(probe, &ipc_body);
                put_probemng_lock();
                (void)send_ipc_msg(__probe_mng_snooper->msq_id, (long)probe->probe_type, &ipc_body);
                continue;
            }
        }
        put_probemng_lock();
    }
}

static void __rcv_snooper_cgrp_exit(struct probe_mng_s *probe_mng, char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    char snooper_obj_removed;
    int i, j;
    struct probe_s *probe;
    struct snooper_obj_s *snooper_obj;
    struct ipc_body_s ipc_body;

    for (i = 0; i < PROBE_TYPE_MAX; i++) {
        get_probemng_lock();
        probe = probe_mng->probes[i];
        if (!probe || probe->snooper_type == SNOOPER_TYPE_NONE) {
            put_probemng_lock();
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
            if (need_send_snooper_obj(probe)) {
                __build_ipc_body(probe, &ipc_body);
                put_probemng_lock();
                (void)send_ipc_msg(__probe_mng_snooper->msq_id, (long)probe->probe_type, &ipc_body);
                continue;
            }
        }
        put_probemng_lock();
    }
}

static int rcv_snooper_cgrp_evt(void *ctx, void *data, __u32 size)
{
    struct snooper_cgrp_evt_s *msg_data = (struct snooper_cgrp_evt_s *)data;

    char pod_id[POD_ID_LEN + 1] = {0};
    char con_id[CONTAINER_ABBR_ID_LEN + 1] = {0};
    enum id_ret_t id_ret = get_pod_container_id(msg_data->cgrp_path, pod_id, con_id);

    if (id_ret == ID_FAILED || pod_id[0] == 0 || con_id[0] == 0) {
        DEBUG("[SNOOPER] failed to get pod_id or con_id from snooper_cgrp_evt. "
            "ret = %d, pod_id = %s, con_id = %s\n", id_ret, pod_id, con_id);
        return 0;
    }

    if (msg_data->cgrp_event == CGRP_MK) {
        add_pod_con_map(pod_id, con_id, id_ret);
        if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
            __rcv_snooper_cgrp_exec(__probe_mng_snooper, pod_id, con_id, id_ret);
        }
    } else {
        del_pod_con_map(pod_id, con_id, id_ret);
        if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
            __rcv_snooper_cgrp_exit(__probe_mng_snooper, pod_id, con_id, id_ret);
        }
    }

    return 0;
}

static void loss_data(void *ctx, int cpu, u64 cnt)
{
    // TODO: debugging
}

int load_snooper_bpf(struct probe_mng_s *probe_mng)
{
    int ret = 0;
    struct snooper_bpf *snooper_skel;
    struct bpf_buffer *proc_buf = NULL, *cgrp_buf = NULL;
    int kern_ver = probe_kernel_version();

    LIBBPF_OPTS(bpf_object_open_opts, opts);
    ensure_core_btf(&opts);

    __probe_mng_snooper = probe_mng;

    INIT_BPF_APP(snooper, EBPF_RLIM_LIMITED);

    /* Open load and verify BPF application */
    snooper_skel = snooper_bpf__open_opts(&opts);
    if (!snooper_skel) {
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

    proc_buf = bpf_buffer__new(snooper_skel->maps.snooper_proc_channel, snooper_skel->maps.heap);
    if (proc_buf == NULL) {
        goto end;
    }

    cgrp_buf = bpf_buffer__new(snooper_skel->maps.snooper_cgrp_channel, snooper_skel->maps.heap);
    if (cgrp_buf == NULL) {
        goto end;
    }

    if (snooper_bpf__load(snooper_skel)) {
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

    ret = bpf_buffer__open(proc_buf, rcv_snooper_proc_evt, loss_data, NULL);
    if (ret) {
        ERROR("[SNOOPER] Open 'snooper_proc_channel' bpf_buffer failed.\n");
        goto end;
    }

    ret = bpf_buffer__open(cgrp_buf, rcv_snooper_cgrp_evt, loss_data, NULL);
    if (ret) {
        ERROR("[SNOOPER] Open 'snooper_cgrp_channel' bpf_buffer failed.\n");
        goto end;
    }
    probe_mng->snooper_proc_pb = proc_buf;
    probe_mng->snooper_cgrp_pb = cgrp_buf;
    probe_mng->snooper_skel = snooper_skel;
    probe_mng->btf_custom_path = opts.btf_custom_path;

    return 0;

end:
    if (snooper_skel) {
        snooper_bpf__destroy(snooper_skel);
        probe_mng->snooper_skel = NULL;
    }

    cleanup_core_btf(&opts);
    bpf_buffer__free(proc_buf);
    bpf_buffer__free(cgrp_buf);
    return -1;
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
