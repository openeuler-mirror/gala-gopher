#!/bin/bash

# Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
# gala-gopher licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#    http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# Author: Vchanger
# Description: scripts to init probe default settings
# Created: 2023-07-04

GOPHER_INITIAL_CONF="/etc/gala-gopher/probes.init"
GOPHER_CMD_SOCK_PATH="/var/run/gala_gopher/gala_gopher_cmd.sock"
GOPHER_PIDFILE="/var/run/gala_gopher/gala-gopher.pid"
MAX_INIT_NUM=30
GOPHER_CUSTOM_JSON="/etc/gala-gopher/gala-gopher-custom.json"
MAX_ATTEMPTS=20

PROBES=(
    "baseinfo"
    "virt"
    "flamegraph"
    "l7"
    "tcp"
    "socket"
    "io"
    "proc"
    "jvm"
    "postgre_sli"
    "opengauss_sli"
    "nginx"
    "lvs"
    "kafka"
    "tprofiling"
    "hw"
    "ksli"
    "container"
    "sermant"
    "sli"
    "flowtracer"
    )

function check_custom()
{
    if [ -e "$GOPHER_CUSTOM_JSON" ] && [ -s "$GOPHER_CUSTOM_JSON" ]; then
        custome_keys=$(cat "$GOPHER_CUSTOM_JSON" | tr -d '\n' | tr -s ' ' | sed 's/"[[:space:]]*{/{/g; s/:[[:space:]]*{/:{/g; s/{/{\n/g; s/}/}\n/g' | grep -o '"[^"]*"[[:space:]]*:{' | cut -d '"' -f 2)
        for key in $custome_keys; do
            if [ -n "$key" ]; then
                PROBES+=("$key")
            fi
        done
    fi
    echo "PROBES=(${PROBES[*]})"
}

function check_gopher_running()
{
    local attempt=0

    while [ $attempt -lt $MAX_ATTEMPTS ]; do
        if [ -f ${GOPHER_PIDFILE} ] && [ ! -L ${GOPHER_PIDFILE} ]; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.5
    done
    return 1
}

function check_unix_socket_listen()
{
    ss -xl src ${GOPHER_CMD_SOCK_PATH} | grep -q ${GOPHER_CMD_SOCK_PATH}
    return $?
}

function check_cmd_server()
{
    while ! check_unix_socket_listen ; do
        if ! check_gopher_running ; then
            exit 1
        fi
        sleep 0.5
    done
}

function init_probes_json()
{
    i=0
    while read line; do
        if [ -z "$line" ] || [[ $line =~ ^#.* ]]; then
            continue
        fi
        url=$(echo $line | awk '{print $1}')
        if [ -z "$url" ] ; then
            exit 1
        fi

        put_data=$(echo $line | cut -d ' ' -f 1 --complement | sed 's/[[:space:]]//g')
        if [ -z "$put_data" ] ; then
            exit 1
        fi

        gopher-ctl probe set "$url" "$put_data" >/dev/null
        let i++;
        if [ $i -gt $MAX_INIT_NUM ] ; then
            echo "[PROBE_INIT] Num of inited probes exceeds ${MAX_INIT_NUM}, config in excess will be ignored."
            break;
        fi
    done < ${GOPHER_INITIAL_CONF}
}

function save_probes_json()
{
    if [ -f ${GOPHER_INITIAL_CONF} ]; then
        > ${GOPHER_INITIAL_CONF}
    else
        exit 1
    fi

    check_custom
    for url in "${PROBES[@]}"; do
        response=$(gopher-ctl probe get "$url")
        if [ -z "${response}" ] || echo "${response}" | grep -qi "failed" || [ "${response}" = "{}" ]; then
            continue
        else
            echo "${url} ${response}" >> ${GOPHER_INITIAL_CONF}
        fi
    done
}

check_cmd_server

if [ "$1" = "--init" ];then
    init_probes_json
    exit
fi

if [ "$1" = "--save" ];then
    save_probes_json
    #clean_bpf_map
    /usr/bin/rm -rf /sys/fs/bpf/gala-gopher/*
    exit
fi
