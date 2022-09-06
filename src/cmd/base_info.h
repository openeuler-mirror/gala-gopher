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
 * Author: njlzk
 * Create: 2021-10-12
 * Description: provide gala-gopher cmd
 ******************************************************************************/
#ifndef __BASE_INFO_H__
#define __BASE_INFO_H__

#define GOPHER_OK       0
#define GOPHER_ERR      (-1)

#define GALA_GOPHER_LISTEN_LEN            5
#define GALA_GOPHER_RUN_DIR               "/var/run/gala_gopher/"
#define GALA_GOPHER_CMD_SOCK_PATH_NAME    "/var/run/gala_gopher/gala_gopher_cmd.sock"
#define GALA_GOPHER_FILE_PERMISSION       0700

#define GOPHER_CMD_REQUEST_STATUS_FAILED1    "Failed to get the request."
#define GOPHER_CMD_REQUEST_STATUS_FAILED2    "Failed to process the request."

#define GOPHER_CMD_LINE_MIN           2
#define GOPHER_CMD_LINE_MAX           3
#define RESULT_INFO_LEN_MAX           1024


#define GOPHER_CMD_KEY1           "show"
#define GOPHER_CMD_KEY1_VALUE1    "config_path"

char *g_cmdShowItemTbl[] = {
    GOPHER_CMD_KEY1_VALUE1,
};


enum GopherCmdType {
    GOPHER_GET_CONFIG_PATH,
    GOPHER_SET_PROBE_UP,
    GOPHER_SET_PROBE_DOWN,
};



#define GOPHER_CMD_KEY_LEN_MAX        32
#define GOPHER_CMD_VALUE_LEN_MAX      32
struct GopherCmdRequest {
    enum GopherCmdType cmdType;
    char cmdKey[GOPHER_CMD_KEY_LEN_MAX];
    char cmdValue[GOPHER_CMD_VALUE_LEN_MAX];
};

#endif
