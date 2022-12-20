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
 * Author: Mr.lu
 * Create: 2022-08-18
 * Description: flame graph defined
 ******************************************************************************/
#ifndef __GOPHER_FLAME_GRAPH_H__
#define __GOPHER_FLAME_GRAPH_H__

#pragma once

#include "svg.h"
#include "stackprobe.h"

void wr_flamegraph(struct stack_svg_mng_s *svg_mng, struct stack_trace_histo_s *head, int en_type,
    struct post_server_s *post_server);
int set_flame_graph_path(struct stack_svg_mng_s *svg_mng, const char* path, const char *flame_name);
int set_post_server(struct post_server_s *post_server, const char *pyroscopeServer);
void clean_post_server();
#endif
