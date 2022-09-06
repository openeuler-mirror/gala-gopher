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
 * Author: wo_cow
 * Create: 2022-06-10
 * Description: cgprobe kernel header file
 ******************************************************************************/
#ifndef __CGROUP_H__
#define __CGROUP_H__

struct mem_cgroup_gauge {
    __u64 cgroup_id;
    unsigned int nr_pages;
    int oom_order;
    __u64 last_report_ts_nsec;
};

struct ns_args_s {
    __u64 period;               // Sampling period, unit ns
};

#endif