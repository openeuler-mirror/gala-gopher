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
 * Description: snooper bpf
 ******************************************************************************/
#ifndef __GOPHER_SNOOPER_BPF__
#define __GOPHER_SNOOPER_BPF__

#pragma once


enum cgrp_event_t {
    CGRP_MK,
    CGRP_RM,
};
#define MAX_CGRP_PATH 512

struct snooper_cgrp_evt_s {
    enum cgrp_event_t cgrp_event;
    char cgrp_path[MAX_CGRP_PATH];
};

enum proc_event_t {
    PROC_EXEC,
    PROC_EXIT
};
struct snooper_proc_evt_s {
    enum proc_event_t proc_event;
    char filename[PATH_LEN];
    u32 pid;
};


#endif

