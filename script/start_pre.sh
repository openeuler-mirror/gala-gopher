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
# Author:
# Description: scripts to prepare gopher before starting
# Created: 2024-05-13

SYS_UUID_FILE=/opt/gala-gopher/machine_id

function gen_sys_uuid_file()
{
    if [ -f /sys/class/dmi/id/product_uuid ] ; then
        cat /sys/class/dmi/id/product_uuid > $SYS_UUID_FILE
        chmod 440 $SYS_UUID_FILE || exit 1
    fi
}

gen_sys_uuid_file
