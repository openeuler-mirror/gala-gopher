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
RETRY_COUNT=5

function check_cmd_server()
{
    i=0
    while [ ! -e $GOPHER_CMD_SOCK_PATH ] ; do
        sleep 1
        let i+=1
        if [ $i -ge ${RETRY_COUNT} ] ; then
            exit 1
        fi
    done
}

function init_probes_json()
{
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

        gopher-ctl probe set "$url" "$put_data"
    done < ${GOPHER_INITIAL_CONF}
}

check_cmd_server
init_probes_json