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
 * Description: syscall defined
 ******************************************************************************/
#ifndef __GOPHER_SYSCALL_H__
#define __GOPHER_SYSCALL_H__

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/syscall.h>

#pragma once

#define setns(FD, NSTYPE) syscall(__NR_setns, (int)(FD), (int)(NSTYPE))
#define open_pid(PID, FLAGS) syscall(__NR_pidfd_open, (int)(PID), (int)(FLAGS))

#define perf_event_open(attr, pid, cpu, group_id, flags) syscall(__NR_perf_event_open, (attr), pid, cpu, group_id, flags)

#define NR_CPUS   sysconf(_SC_NPROCESSORS_CONF)
#endif
