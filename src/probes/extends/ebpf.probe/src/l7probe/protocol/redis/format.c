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
 * Create: 2023-04-13
 * Description:
 ******************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <json_tool.h>
#include "../utils/string_utils.h"
#include "common.h"
#include "format.h"

const char *cmd[] = {
    "ACL LOAD",
    "ACL SAVE",
    "ACL LIST",
    "ACL USERS",
    "ACL GETUSER",
    "ACL SETUSER",
    "ACL DELUSER",
    "ACL CAT",
    "ACL GENPASS",
    "ACL WHOAMI",
    "ACL LOG",
    "ACL HELP",
    "APPEND",
    "AUTH",
    "BGREWRITEAOF",
    "BGSAVE",
    "BITCOUNT",
    "BITFIELD",
    "BITOP",
    "BITPOS",
    "BLPOP",
    "BRPOP",
    "BRPOPLPUSH",
    "BLMOVE",
    "BZPOPMIN",
    "BZPOPMAX",
    "CLIENT CACHING",
    "CLIENT ID",
    "CLIENT INFO",
    "CLIENT KILL",
    "CLIENT LIST",
    "CLIENT GETNAME",
    "CLIENT GETREDIR",
    "CLIENT UNPAUSE",
    "CLIENT PAUSE",
    "CLIENT REPLY",
    "CLIENT SETNAME",
    "CLIENT TRACKING",
    "CLIENT TRACKINGINFO",
    "CLIENT UNBLOCK",
    "CLUSTER ADDSLOTS",
    "CLUSTER BUMPEPOCH",
    "CLUSTER COUNT-FAILURE-REPORTS",
    "CLUSTER COUNTKEYSINSLOT",
    "CLUSTER DELSLOTS",
    "CLUSTER FAILOVER",
    "CLUSTER FLUSHSLOTS",
    "CLUSTER FORGET",
    "CLUSTER GETKEYSINSLOT",
    "CLUSTER INFO",
    "CLUSTER KEYSLOT",
    "CLUSTER MEET",
    "CLUSTER MYID",
    "CLUSTER NODES",
    "CLUSTER REPLICATE",
    "CLUSTER RESET",
    "CLUSTER SAVECONFIG",
    "CLUSTER SET-CONFIG-EPOCH",
    "CLUSTER SETSLOT",
    "CLUSTER SLAVES",
    "CLUSTER REPLICAS",
    "CLUSTER SLOTS",
    "COMMAND",
    "COMMAND COUNT",
    "COMMAND GETKEYS",
    "COMMAND INFO",
    "CONFIG GET",
    "CONFIG REWRITE",
    "CONFIG SET",
    "CONFIG RESETSTAT",
    "COPY",
    "DBSIZE",
    "DEBUG OBJECT",
    "DEBUG SEGFAULT",
    "DECR",
    "DECRBY",
    "DEL",
    "DISCARD",
    "DUMP",
    "ECHO",
    "EVAL",
    "EVALSHA",
    "EXEC",
    "EXISTS",
    "EXPIRE",
    "EXPIREAT",
    "FAILOVER",
    "FLUSHALL",
    "FLUSHDB",
    "GEOADD",
    "GEOHASH",
    "GEOPOS",
    "GEODIST",
    "GEORADIUS",
    "GEORADIUSBYMEMBER",
    "GEOSEARCH",
    "GEOSEARCHSTORE",
    "GET",
    "GETBIT",
    "GETDEL",
    "GETEX",
    "GETRANGE",
    "GETSET",
    "HDEL",
    "HELLO",
    "HEXISTS",
    "HGET",
    "HGETALL",
    "HINCRBY",
    "HINCRBYFLOAT",
    "HKEYS",
    "HLEN",
    "HMGET",
    "HMSET",
    "HSET",
    "HSETNX",
    "HRANDFIELD",
    "HSTRLEN",
    "HVALS",
    "INCR",
    "INCRBY",
    "INCRBYFLOAT",
    "INFO",
    "LOLWUT",
    "KEYS",
    "LASTSAVE",
    "LINDEX",
    "LINSERT",
    "LLEN",
    "LPOP",
    "LPOS",
    "LPUSH",
    "LPUSHX",
    "LRANGE",
    "LREM",
    "LSET",
    "LTRIM",
    "MEMORY DOCTOR",
    "MEMORY HELP",
    "MEMORY MALLOC-STATS",
    "MEMORY PURGE",
    "MEMORY STATS",
    "MEMORY USAGE",
    "MGET",
    "MIGRATE",
    "MODULE LIST",
    "MODULE LOAD",
    "MODULE UNLOAD",
    "MONITOR",
    "MOVE",
    "MSET",
    "MSETNX",
    "MULTI",
    "OBJECT",
    "PERSIST",
    "PEXPIRE",
    "PEXPIREAT",
    "PFADD",
    "PFCOUNT",
    "PFMERGE",
    "PING",
    "PSETEX",
    "PSUBSCRIBE",
    "PUBSUB",
    "PTTL",
    "PUBLISH",
    "PUNSUBSCRIBE",
    "QUIT",
    "RANDOMKEY",
    "READONLY",
    "READWRITE",
    "RENAME",
    "RENAMENX",
    "RESET",
    "RESTORE",
    "ROLE",
    "RPOP",
    "RPOPLPUSH",
    "LMOVE",
    "RPUSH",
    "RPUSHX",
    "SADD",
    "SAVE",
    "SCARD",
    "SCRIPT DEBUG",
    "SCRIPT EXISTS",
    "SCRIPT FLUSH",
    "SCRIPT KILL",
    "SCRIPT LOAD",
    "SDIFF",
    "SDIFFSTORE",
    "SELECT",
    "SET",
    "SETBIT",
    "SETEX",
    "SETNX",
    "SETRANGE",
    "SHUTDOWN",
    "SINTER",
    "SINTERSTORE",
    "SISMEMBER",
    "SMISMEMBER",
    "SLAVEOF",
    "REPLICAOF",
    "SLOWLOG",
    "SMEMBERS",
    "SMOVE",
    "SORT",
    "SPOP",
    "SRANDMEMBER",
    "SREM",
    "STRALGO",
    "STRLEN",
    "SUBSCRIBE",
    "SUNION",
    "SUNIONSTORE",
    "SWAPDB",
    "SYNC",
    "PSYNC",
    "TIME",
    "TOUCH",
    "TTL",
    "TYPE",
    "UNSUBSCRIBE",
    "UNLINK",
    "UNWATCH",
    "WAIT",
    "WATCH",
    "ZADD",
    "ZCARD",
    "ZCOUNT",
    "ZDIFF",
    "ZDIFFSTORE",
    "ZINCRBY",
    "ZINTER",
    "ZINTERSTORE",
    "ZLEXCOUNT",
    "ZPOPMAX",
    "ZPOPMIN",
    "ZRANDMEMBER",
    "ZRANGESTORE",
    "ZRANGE",
    "ZRANGEBYLEX",
    "ZREVRANGEBYLEX",
    "ZRANGEBYSCORE",
    "ZRANK",
    "ZREM",
    "ZREMRANGEBYLEX",
    "ZREMRANGEBYRANK",
    "ZREMRANGEBYSCORE",
    "ZREVRANGE",
    "ZREVRANGEBYSCORE",
    "ZREVRANK",
    "ZSCORE",
    "ZUNION",
    "ZMSCORE",
    "ZUNIONSTORE",
    "SCAN",
    "SSCAN",
    "HSCAN",
    "ZSCAN",
    "XINFO",
    "XADD",
    "XTRIM",
    "XDEL",
    "XRANGE",
    "XREVRANGE",
    "XLEN",
    "XREAD",
    "XGROUP",
    "XREADGROUP",
    "XACK",
    "XCLAIM",
    "XAUTOCLAIM",
    "XPENDING",
    "LATENCY DOCTOR",
    "LATENCY GRAPH",
    "LATENCY HISTORY",
    "LATENCY LATEST",
    "LATENCY RESET",
    "LATENCY HELP",
    "SENTINEL",
    "REPLCONF ACK",
    NULL
};

// Returns a JSON string that formats the input arguments as a JSON array.
static char *format_as_json_array(UT_array *args)
{
    void *json_array = Json_CreateArray();
    for (int i = 0; i < utarray_len(args); i++) {
        char *str = *(char **) utarray_eltptr(args, i);
        Json_AddStringItemToArray(json_array, str);
    }
    char *json_str = Json_PrintUnformatted(json_array);
    Json_Delete(json_array);
    return json_str;
}

static char *format_as_str_separated_by_space(UT_array *args)
{
    int total_len = 0;
    int len = utarray_len(args);
    for (int i = 0; i < len; ++i) {
        char *str = *(char **) utarray_eltptr(args, i);
        total_len += (strlen(str) + 1);
    }
    char *result = (char *) malloc((total_len + 1) * sizeof(char));
    if (result == NULL) {
        ERROR("[Redis Parse] The result malloc failed.\n");
        return NULL;
    }
    memset(result, 0, (total_len + 1) * sizeof(char));
    result[0] = '\0';
    for (int i = 0; i < len; ++i) {
        char *str = *(char **) utarray_eltptr(args, i);
        strcat(result, str);
        if (i != len - 1) {
            strcat(result, " ");
        }
    }
    return result;
}

static bool find_cmd(char *opt_cmd)
{
    int i = 0;
    while (cmd[i] != NULL) {
        if (strcmp(opt_cmd, cmd[i]) == 0) {
            return true;
        }
        i++;
    }
    return false;
}

static bool get_redis_cmd(UT_array *payloads, char *res)
{
    const int double_cmd_num = 2;
    if (utarray_len(payloads) == 0) {
        return false;
    }

    // Search the double-words command first.
    if (utarray_len(payloads) >= double_cmd_num) {
        char *first = *(char **) utarray_eltptr(payloads, 0);
        char *second = *(char **) utarray_eltptr(payloads, 1);
        size_t size = strlen(first) + strlen(second) + 2;
        char des[size];

        // 使用空格拼接redis double-words command
        strcpy(des, first);
        strcat(des, " ");
        strcat(des, second);

        char *opt_cmd = str_to_upper(des);
        if (find_cmd(opt_cmd)) {
            strcpy(res, opt_cmd);
            utarray_erase(payloads, 0, double_cmd_num);
            return true;
        }
    }
    char *opt_cmd = str_to_upper(*(char **) utarray_front(payloads));
    if (find_cmd(opt_cmd)) {
        strcpy(res, opt_cmd);
        utarray_erase(payloads, 0, 1);
        return true;
    }
    return false;
}

void format_array_msg(UT_array *payloads, struct redis_msg_s *msg)
{
    const size_t COMMAND_MAX_SIZE = 50;
    char command[COMMAND_MAX_SIZE];
    bool success = get_redis_cmd(payloads, command);
    if (!success) {
        // If no command is found, this array message is formatted as JSON array.
        msg->payload = format_as_json_array(payloads);
        return;
    }

    msg->command = strdup(command);
    msg->payload = format_as_str_separated_by_space(payloads);
}
