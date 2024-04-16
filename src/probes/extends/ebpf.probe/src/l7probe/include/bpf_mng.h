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
 * Author: wo_cow
 * Create: 2023-02-20
 * Description: pod definitions
 ******************************************************************************/
#ifndef __BPF_MNG_H__
#define __BPF_MNG_H__

#include "bpf.h"
#include "l7_common.h"

int l7_load_probe_kern_sock(struct l7_mng_s *l7_mng, struct bpf_prog_s *prog);
int l7_load_probe_libssl(struct l7_mng_s *l7_mng, struct bpf_prog_s *prog, const char *libssl_path);

#endif