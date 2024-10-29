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
 * Author: algorithmofdish
 * Create: 2023-04-03
 * Description: definition of the pthread api that need to be profiled
 ******************************************************************************/
#ifndef __PTHREAD_TABLE_H__
#define __PTHREAD_TABLE_H__

enum {
    PTHREAD_UNKNOWN_ID = 0,
    PTHREAD_MUTEX_LOCK_ID,
    PTHREAD_MUTEX_TIMEDLOCK_ID,
    PTHREAD_MUTEX_TRYLOCK_ID,
    PTHREAD_RWLOCK_RDLOCK_ID,
    PTHREAD_RWLOCK_WRLOCK_ID,
    PTHREAD_RWLOCK_TIMEDRDLOCK_ID,
    PTHREAD_RWLOCK_TIMEDWRLOCK_ID,
    PTHREAD_RWLOCK_TRYRDLOCK_ID,
    PTHREAD_RWLOCK_TRYWRLOCK_ID,
    PTHREAD_SPIN_LOCK_ID,
    PTHREAD_SPIN_TRYLOCK_ID,
    PTHREAD_TIMEDJOIN_NP_ID,
    PTHREAD_TRYJOIN_NP_ID,
    PTHREAD_YIELD_ID,
    SEM_TIMEDWAIT_ID,
    SEM_TRYWAIT_ID,
    SEM_WAIT_ID,
    PTHREAD_MAX_ID
};

#define PTHREAD_MUTEX_LOCK_NAME         "pthread_mutex_lock"
#define PTHREAD_MUTEX_TIMEDLOCK_NAME    "pthread_mutex_timedlock"
#define PTHREAD_MUTEX_TRYLOCK_NAME      "pthread_mutex_trylock"
#define PTHREAD_RWLOCK_RDLOCK_NAME      "pthread_rwlock_rdlock"
#define PTHREAD_RWLOCK_WRLOCK_NAME      "pthread_rwlock_wrlock"
#define PTHREAD_RWLOCK_TIMEDRDLOCK_NAME "pthread_rwlock_timedrdlock"
#define PTHREAD_RWLOCK_TIMEDWRLOCK_NAME "pthread_rwlock_timedwrlock"
#define PTHREAD_RWLOCK_TRYRDLOCK_NAME   "pthread_rwlock_tryrdlock"
#define PTHREAD_RWLOCK_TRYWRLOCK_NAME   "pthread_rwlock_trywrlock"
#define PTHREAD_SPIN_LOCK_NAME          "pthread_spin_lock"
#define PTHREAD_SPIN_TRYLOCK_NAME       "pthread_spin_trylock"
#define PTHREAD_TIMEDJOIN_NP_NAME       "pthread_timedjoin_np"
#define PTHREAD_TRYJOIN_NP_NAME         "pthread_tryjoin_np"
#define PTHREAD_YIELD_NAME              "pthread_yield"
#define SEM_TIMEDWAIT_NAME              "sem_timedwait"
#define SEM_TRYWAIT_NAME                "sem_trywait"
#define SEM_WAIT_NAME                   "sem_wait"

#endif