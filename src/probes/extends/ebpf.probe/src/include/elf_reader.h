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
 * Author: dowzyx
 * Create: 2021-12-08
 * Description: elf parse
 ******************************************************************************/
#ifndef __ELF_READER_H__
#define __ELF_READER_H__

#define BPF_ELF_DESC(desc) 1

int get_glibc_path(const char *container_id, char *path, unsigned int len);

int get_exec_file_path(const char *binary_file, const char *specified_path, const char *container_id,
                        char **res_buf, int res_len);

void free_exec_path_buf(char **ptr, int len);

#endif
