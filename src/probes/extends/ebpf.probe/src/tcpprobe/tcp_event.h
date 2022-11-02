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
 * Author: luzhihao
 * Create: 2022-07-28
 * Description: tcp event
 ******************************************************************************/
#ifndef __TCP_EVENT__H
#define __TCP_EVENT__H

#pragma once

#include "args.h"
#include "tcpprobe.h"

void report_tcp_syn_rtt_evt(struct probe_params *args, struct tcp_metrics_s *metrics);
void report_tcp_abn_evt(struct probe_params *args, struct tcp_metrics_s *metrics);
void report_tcp_win_evt(struct probe_params *args, struct tcp_metrics_s *metrics);

#endif
