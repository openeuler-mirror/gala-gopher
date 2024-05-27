/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Hubble_Zhu
 * Create: 2021-04-12
 * Description:
 ******************************************************************************/
#ifndef __BASE_H__
#define __BASE_H__

#pragma once

#define GALA_GOPHER_INFO(description)   1

// ======== COMMON ========
// fifo
#define MAX_FIFO_NUM          32
#define MAX_FIFO_SIZE         1024

// meta
#define MAX_META_PATH_LEN           2048
#define MAX_FIELD_DESCRIPTION_LEN   256
#define MAX_FIELD_TYPE_LEN          64
#define MAX_FIELD_NAME_LEN          64
#define MAX_MEASUREMENT_NAME_LEN    64
#define MAX_FIELDS_NUM              128
#define MAX_META_VERSION_LEN        16

// ingress
#define MAX_EPOLL_SIZE        1024
#define MAX_EPOLL_EVENTS_NUM  512

// egress
#define MAX_DATA_STR_LEN      8192

// kafka
#define MAX_KAFKA_ERRSTR_SIZE 512

// common
#define MAX_THREAD_NAME_LEN   128
#define MAX_LANGUAGE_TYPE_LEN  32

// ======== CONFIG ========
// global config
#define MAX_PIN_PATH_LEN 128

// kafka config
#define MAX_KAFKA_BROKER_LEN  32
#define MAX_KAFKA_TOPIC_LEN   32
#define KAFKA_COMPRESSION_CODEC_LEN   32

// probe config
#define MAX_PROBE_NAME_LEN    32

// extend probe config
#define MAX_EXTEND_PROBE_COMMAND_LEN 128
#define MAX_PARAM_LEN 128
#define MAX_COMMAND_LEN 1024

// kafka switch
typedef enum {
    KAFKA_SWITCH_ON = 0,
    KAFKA_SWITCH_OFF,
    KAFKA_SWITCH_MAX
} KafkaSwitch;

// probe status
typedef enum {
    PROBE_SWITCH_AUTO = 0,
    PROBE_SWITCH_ON,
    PROBE_SWITCH_OFF,
    PROBE_SWITCH_MAX
} ProbeSwitch;

// out_channel
typedef enum {
    OUT_CHNL_NULL = 0,
    OUT_CHNL_LOGS,
    OUT_CHNL_KAFKA,
    OUT_CHNL_WEB_SERVER,
    OUT_CHNL_JSON,

    OUT_CHNL_MAX
} OutChannelType;

#define GALA_META_DIR_PATH            "/opt/gala-gopher/meta"
#define GALA_CONF_PATH_DEFAULT        "/etc/gala-gopher/gala-gopher.conf"
#define GALA_GOPHER_RUN_DIR           "/var/run/gala_gopher/"
#define GALA_GOPHER_RUN_DIR_MODE      0750

#endif

