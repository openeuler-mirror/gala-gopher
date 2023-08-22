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
 * Description: probe param parser
 ******************************************************************************/
#ifndef __PROBE_PARAMS_PARSER__
#define __PROBE_PARAMS_PARSER__

#include <cjson/cJSON.h>

int parse_params(struct probe_s *probe, const cJSON *params_json);
void set_default_params(struct probe_s *probe);

void probe_params_to_json(struct probe_s *probe, cJSON *json);

#endif

