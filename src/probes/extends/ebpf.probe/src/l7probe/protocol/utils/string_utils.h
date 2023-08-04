/*******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: niebin
 * Create: 2023-04-14
 * Description:
 ******************************************************************************/

#ifndef __STRING_UTILS_H__
#define __STRING_UTILS_H__

#pragma once

#include <stdbool.h>

bool is_end_with(char *str, const char *suffix);

char *remove_suffix(char *str, size_t n);

char *str_to_upper(char *str);

#endif