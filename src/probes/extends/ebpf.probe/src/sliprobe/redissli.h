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
 * Create: 2022-3-8
 * Description: redis SLI probe header file
 ******************************************************************************/
#ifndef __REDISSLI_H__
#define __REDISSLI_H__

#define __RDS_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

#if (__RDS_VERSION(RDS_VER_MAJOR, RDS_VER_MINOR, RDS_VER_PATCH) == __RDS_VERSION(6, 2, 1))
#include "redis_6.2.1.h"
#else
#error Unsupported redis version.
#endif

typedef unsigned long long u64;
typedef unsigned int u32;

#define MAX_REDIS_CMD_LEN 24
#define MAX_CACHED_CMDS 1               // 缓存的 redis 命令数量，受限于 BPF 程序的 512B 栈大小

struct conn_key_t {
    int tgid;                           // 连接所属进程的 tgid
    int fd;                             // 连接对应 socket 的文件描述符
};

struct conn_id_t {
    int tgid;
    int fd;
    u64 ts_nsec;                        // 连接创建的时间戳
};

enum reply_store_t {
    NO_STORAGE = 0,
    STATIC_BUFFER,
    DYNAMIC_LIST,
};

struct redis_cmd_data_t {
    char name[MAX_REDIS_CMD_LEN];       // redis 请求执行的命令名称，如 get 、set 等
    u64 start_ts_nsec;                  // redis 请求进入应用层的时间点
    u64 end_ts_nsec;                    // redis 请求离开应用层的时间点
    int has_reply;                      // redis 请求是否向客户端发送了响应报文
    enum reply_store_t store_type;      // redis 请求的应答报文的存储介质类型，redis提供两种应答报文的存储介质：静态buffer和动态list
    union {
        u64 wr_bufpos;                 // redis 请求的应答报文在静态buffer的绝对位置
        u64 wr_listpos;                // redis 请求的应答报文在动态list的绝对位置
    };
    int finished;
};
struct conn_data_t {
    struct conn_id_t id;
    u64 last_read_ts_nsec;              // 上一次读 redis 请求的时间点
    u64 last_smp_ts_nsec;               // 上一次采样的时间点
    u64 rd_bufsize;
    u64 rd_listsize;
    u64 cur_bufpos;                     // redis 客户端的静态buffer应答缓冲区的已读位置
    u64 cur_listpos;                    // redis 客户端的动态list应答缓冲区的已读位置
    unsigned int cmd_nums;              // 当前缓存的 redis 请求的数量
    struct redis_cmd_data_t cmds[MAX_CACHED_CMDS];  // redis 请求的统计信息
};

struct cmd_event_data_t {
    struct conn_id_t conn_id;
    char name[MAX_REDIS_CMD_LEN];
    u64 timeout_nsec;
};

#endif