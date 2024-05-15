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
GOPHER_CMD_SOCK_PATH="/var/run/gala_gopher/gala_gopher_cmd.sock"
RETRY_COUNT=5
ssl_auth_on="on"
rest_server_port=""
rest_server_ssl_auth=""
rest_server_private_key=""
rest_server_cert_file=""
listen_on=""

function load_gopher_conf()
{
    if [ ! -f ${GOPHER_CONF} ] || [ ! -f ${GOPHER_INITIAL_CONF} ] ; then
        exit 1;
    fi
    rest_server_line_num=$(sed -ne '/rest_api_server/=' $GOPHER_CONF)

    rest_server_port_line=$(sed -n "$rest_server_line_num,/port =/p" $GOPHER_CONF | tail -n1)
    rest_server_port=$(echo $rest_server_port_line  | awk -F ' = ' '{print $2}')
    rest_server_port=${rest_server_port%;}

    rest_server_ssl_auth_line=$(sed -n "$rest_server_line_num,/ssl_auth =/p" $GOPHER_CONF | tail -n1)
    rest_server_ssl_auth=$(echo $rest_server_ssl_auth_line | awk -F ' = ' '{print $2}')
    rest_server_ssl_auth=$(echo ${rest_server_ssl_auth%;} |  sed 's/"//g')

    rest_server_private_key_line=$(sed -n "$rest_server_line_num,/private_key =/p" $GOPHER_CONF | tail -n1)
    rest_server_private_key=$(echo $rest_server_private_key_line | awk -F ' = ' '{print $2}')
    rest_server_private_key=$(echo ${rest_server_private_key%;} |  sed 's/"//g')

    rest_server_cert_file_line=$(sed -n "$rest_server_line_num,/cert_file =/p" $GOPHER_CONF | tail -n1)
    rest_server_cert_file=$(echo $rest_server_cert_file_line | awk -F ' = ' '{print $2}')
    rest_server_cert_file=$(echo ${rest_server_cert_file%;} |  sed 's/"//g')

    listen_on=$(cat $GOPHER_CONF | grep "listen_on" | awk -F ' = ' '{print $2}')
    listen_on=$(echo ${listen_on%;})

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

        if test $listen_on = "false"; then
            gopher-ctl probe set "$url" "$put_data"
        else
            if test $rest_server_ssl_auth = $ssl_auth_on ; then
                curl --cert $rest_server_cert_file --key $rest_server_private_key -k -s -X PUT https://localhost:${rest_server_port}/$url -d json=${put_data} -o /dev/null
            else
                curl -s -X PUT http://localhost:${rest_server_port}/$url -d json=${put_data} -o /dev/null
            fi
        fi
    done < ${GOPHER_INITIAL_CONF}
}

load_gopher_conf
if test $listen_on != "false"; then
    check_rest_server
else
    check_cmd_server
fi
init_probes_json