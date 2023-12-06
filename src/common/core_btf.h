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
 * Create: 2023-11-18
 * Description: eBPF CO-RE BTF
 ******************************************************************************/
#ifndef __CORE_BTF_H__
#define __CORE_BTF_H__

#pragma once
#include <bpf/libbpf.h>

int ensure_core_btf(struct bpf_object_open_opts* opts);
void cleanup_core_btf(struct bpf_object_open_opts* opts);

#endif

