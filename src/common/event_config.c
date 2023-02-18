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
 * Author: dowzyx
 * Create: 2023-01-06
 * Description: parse event config
 ******************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <libconfig.h>
#include "event_config.h"

#define EVT_MULTY_LANG_RES_FILE_PATH    "/etc/gala-gopher/res/event_multy_language.rc"

static void event_config_destroy(eventConfig *evt);

static eventConfig *event_config_create(void)
{
    eventConfig *evt = NULL;
    evt = (eventConfig *)malloc(sizeof(eventConfig));
    if (evt == NULL) {
        return NULL;
    }
    memset(evt, 0, sizeof(eventConfig));
    return evt;
}

static void event_config_destroy(eventConfig *evt)
{
    if (evt == NULL) {
        return;
    }
    free(evt);
    return;
}

static EventsConfig *events_config_create(void)
{
    EventsConfig *conf = NULL;
    conf = (EventsConfig *)malloc(sizeof(EventsConfig));
    if (conf == NULL) {
        return NULL;
    }
    memset(conf, 0, sizeof(EventsConfig));

    return conf;
}

static void events_config_destroy(EventsConfig *conf)
{
    if (conf == NULL) {
        return;
    }

    for (int i = 0; i < conf->num; i++) {
        if (conf->events[i] != NULL) {
            event_config_destroy(conf->events[i]);
        }
    }
    free(conf);
    return;
}

static int event_config_add(EventsConfig *conf, eventConfig *evt)
{
    if (conf->num >= MAX_EVENT_NUM) {
        return -1;
    }
    conf->events[conf->num] = evt;
    conf->num++;

    return 0;
}

static int field_load(jsonfieldsConfig *field, config_setting_t *field_config)
{
    int ret = 0;
    const char *str_val;

    (void)memset(field, 0, sizeof(jsonfieldsConfig));
    ret = config_setting_lookup_string(field_config, "metric", &str_val);
    if (ret == 0) {
        ERROR("[EVENT] load filed metric failed.\n");
        return -1;
    }
    (void)strncpy(field->metric, str_val, MAX_METRIC_NAME_LEN - 1);

    ret = config_setting_lookup_string(field_config, "description", &str_val);
    if (ret == 0) {
        ERROR("[EVENT] load filed description failed.\n");
        return -1;
    }
    (void)strncpy(field->desc, str_val, MAX_EVT_BODY_LEN - 1);

    return 0;
}

static int event_config_load(EventsConfig *conf, eventConfig *evt, config_setting_t *event_config)
{
    int ret = 0;
    const char *entity;

    ret = config_setting_lookup_string(event_config, "entity_name", &entity);
    if (ret == 0) {
        ERROR("[EVENT] load event entity_name failed.\n");
        return -1;
    }
    (void)strncpy(evt->entity_name, entity, MAX_ENTITY_NAME_LEN - 1);

    config_setting_t *fields = config_setting_lookup(event_config, "fields");
    int fields_count = config_setting_length(fields);
    if (fields_count > MAX_EVENT_NUM) {
        ERROR("[EVENT] Too many event fields.\n");
        return -1;
    }

    for (int i = 0; i < fields_count; i++) {
        config_setting_t *field_config = config_setting_get_elem(fields, i);
        ret = field_load(&evt->json_fields[i], field_config);
        if (ret != 0) {
            ERROR("[EVENT] load event fileds failed.\n");
        }
        evt->fields_num++;
    }
    return 0;
}

static int events_config_load(EventsConfig *conf, const char *conf_path, char *grp_name)
{
    int ret = 0;
    config_t cfg;

    config_init(&cfg);
    ret = config_read_file(&cfg, conf_path);
    if (ret == 0) {
        ERROR("[EVENT] config read %s failed.\n", conf_path);
        config_destroy(&cfg);
        return -1;
    }

    config_setting_t *settings = config_lookup(&cfg, grp_name);
    if (settings == NULL) {
        ERROR("[EVENT] config lookup events failed.\n");
        config_destroy(&cfg);
        return -1;
    }
    
    int count = config_setting_length(settings);
    for (int i = 0; i < count; i++) {
        config_setting_t *event_config = config_setting_get_elem(settings, i);
        eventConfig *evt = event_config_create();
        if (evt == NULL) {
            ERROR("[EVENT] malloc event config failed.\n");
            config_destroy(&cfg);
            return -1;
        }

        ret = event_config_load(conf, evt, event_config);
        if (ret != 0) {
            ERROR("[EVENT] load event config failed.\n");
            config_destroy(&cfg);
            event_config_destroy(evt);
            return -1;
        }

        ret = event_config_add(conf, evt);
        if (ret != 0) {
            ERROR("[EVENT] add event config failed.\n");
            config_destroy(&cfg);
            event_config_destroy(evt);
            return -1;
        }
    }

    config_destroy(&cfg);
    return 0;
}

int events_config_init(EventsConfig **conf, char *lang_type)
{
    int ret;
    char grp_name[MAX_EVT_GRP_NAME_LEN];

    if (access(EVT_MULTY_LANG_RES_FILE_PATH, 0) < 0) {
        ERROR("[EVENT] config path error.\n");
        return -1;
    }

    *conf = events_config_create();
    if (*conf == NULL) {
        ERROR("[EVENT] events config create failed.\n");
        return -1;
    }

    grp_name[0] = 0;
    (void)snprintf(grp_name, MAX_EVT_GRP_NAME_LEN - 1, "events_%s", lang_type);
    ret = events_config_load(*conf, EVT_MULTY_LANG_RES_FILE_PATH, grp_name);
    if (ret != 0) {
        ERROR("[EVENT] load events configuration type[%s] failed.\n", grp_name);
        events_config_destroy(*conf);
        *conf = NULL;
        return -1;
    }

    return 0;
}

int get_event_field(EventsConfig *conf, const char *entity, const char *metric, char *desc_fmt)
{
    if (conf == NULL || desc_fmt == NULL) {
        ERROR("[EVENT] get event field failed because input param is NULL.\n");
        return 0;
    }

    for (int i = 0; i < conf->num; i++) {
        if (strcmp(conf->events[i]->entity_name, entity) == 0) {
            eventConfig *_evt = conf->events[i];
            for (int j = 0; j < _evt->fields_num; j++) {
                if (strcmp(_evt->json_fields[j].metric, metric) == 0) {
                    (void)strncpy(desc_fmt, _evt->json_fields[j].desc, MAX_EVT_BODY_LEN - 1);
                    return 1;
                }
            }
        }
    }

    return 0;
}