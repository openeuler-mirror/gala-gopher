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
 * Author: Hubble_Zhu
 * Create: 2021-04-12
 * Description:
 ******************************************************************************/
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdarg.h>

#include "syscall.h"
#include "nprobe_fprintf.h"
#include "probe_mng.h"

#define ZEROPAD 1       /* pad with zero */
#define SIGN    2       /* unsigned/signed long */
#define PLUS    4       /* show plus */
#define SPACE   8       /* space if plus */
#define LEFT    16      /* left justified */
#define SMALL   32      /* Must be 32 == 0x20 */
#define SPECIAL 64      /* 0x */

__thread struct probe_s *g_probe;

void *native_probe_thread_cb(void *arg)
{
    g_probe = (struct probe_s *)arg;

    char thread_name[MAX_THREAD_NAME_LEN];
    snprintf(thread_name, MAX_THREAD_NAME_LEN - 1, "[PROBE]%s", g_probe->name);
    prctl(PR_SET_NAME, thread_name);

    (void)pthread_rwlock_wrlock(&g_probe->rwlock);
    g_probe->pid = (int)gettid();
    (void)pthread_rwlock_unlock(&g_probe->rwlock);

    SET_PROBE_FLAGS(g_probe, PROBE_FLAGS_RUNNING);
    UNSET_PROBE_FLAGS(g_probe, PROBE_FLAGS_STOPPED);

    g_probe->probe_entry(&(g_probe->probe_param));
    SET_PROBE_FLAGS(g_probe, PROBE_FLAGS_STOPPED);
    UNSET_PROBE_FLAGS(g_probe, PROBE_FLAGS_RUNNING);
    clear_ipc_msg((long)g_probe->probe_type);
}

int nprobe_fprintf(FILE *stream, const char *curFormat, ...)
{
    (void)stream;

    char *dataStr = (char *)malloc(MAX_DATA_STR_LEN);
    if (dataStr == NULL) {
        return -1;
    }
    memset(dataStr, 0, MAX_DATA_STR_LEN);

    va_list args;
    va_start(args, curFormat);
    (void)vsnprintf(dataStr, MAX_DATA_STR_LEN, curFormat, args);
    va_end(args);

    int ret = FifoPut(g_probe->fifo, (void *)dataStr);
    if (ret != 0) {
        ERROR("[PROBE %s] fifo full.\n", g_probe->name);
        (void)free(dataStr);
        return -1;
    }

    uint64_t msg = 1;
    ret = write(g_probe->fifo->triggerFd, &msg, sizeof(uint64_t));
    if (ret != sizeof(uint64_t)) {
        ERROR("[PROBE %s] send trigger msg to eventfd failed.\n", g_probe->name);
        return -1;
    }

    return 0;
}

