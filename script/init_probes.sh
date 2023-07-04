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

GOPHER_CONF="/etc/gala-gopher/gala-gopher.conf"
GOPHER_INITIAL_CONF="/etc/gala-gopher/probes.init"
RETRY_COUNT=5
rest_server_port=""

function load_gopher_conf()
{
    if [ ! -f ${GOPHER_CONF} ] || [ ! -f ${GOPHER_INITIAL_CONF} ] ; then
        exit 1;
    fi
    rest_server_line=$(sed -n '/rest_api_server =/{n;n;p}' $GOPHER_CONF)
    rest_server_port=$(echo $rest_server_line  | awk -F ' = ' '{print $2}')
    rest_server_port=${rest_server_port%;}

    if [ -z "${rest_server_port}" ] ; then
        exit 1;
    fi
}

function check_rest_server()
{
    i=0
    while ! netstat -tunpl | grep gala-gopher | \
            grep LISTEN | awk -F ' ' '{print $4}' | grep -q $rest_server_port ; do
        sleep 1
        let i+=1
        if [ $i -ge ${RETRY_COUNT} ] ; then
            exit 1
        fi
    done
}

function init_probes_json()
{
    while read line || [[ -n "${line}" ]] ; do
        [[ $line =~ ^#.* ]] && continue
        url=$(echo $line | awk '{print $1}')
        if [ -z "$url" ] ; then
            exit 1
        fi

        put_data=$(echo $line | awk '{print $2}')
        if [ -z "$put_data" ] ; then
            exit 1
        fi
        curl -s -X PUT http://localhost:${rest_server_port}/$url -d json=${put_data} -o /dev/null
    done < ${GOPHER_INITIAL_CONF}
}

load_gopher_conf
check_rest_server
init_probes_json