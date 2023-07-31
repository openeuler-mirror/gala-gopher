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
 * Author: Vchanger
 * Create: 2023-04-30
 * Description: ipc api
 ******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "ipc.h"

#define IPC_TLV_LEN_DEFAULT ((2 * (sizeof(struct ipc_tlv_s) + sizeof(u32))) \
    + (sizeof(struct ipc_tlv_s) + sizeof(struct probe_params)))

enum ipct_type_e {
    IPCT_PROBE_RANGE = 100,
    IPCT_PROBE_PARAMS = 101,
    IPCT_SNOOPER_NUM = 102
};

enum ipct_subtype_e {
    IPCT_GAUSSDB_IP = 1000,
    IPCT_GAUSSDB_DBNAME,
    IPCT_GAUSSDB_USR,
    IPCT_GAUSSDB_PASS,

    IPCT_CONTAINER_ID,
    IPCT_CONTAINER_NAME,
    IPCT_LIBC_PATH,
    IPCT_LIBSSL_PATH,
    IPCT_POD_ID,
    IPCT_POD_NAME,
    IPCT_POD_IP,

    IPCT_DEV
};

struct ipc_tlv_s {
    u16 type;
    u16 len;
    char value[];
};

struct ipc_msg_s {
    long msg_type;  // Equivalent to enum probe_type_e
    u32 msg_flag;
    u32 msg_len;
    char msg[0];
};

/*
IPC msg format:
                    1byte           2byte           3byte             4byte
         ---|----------------|----------------|----------------|----------------|
        /   |                     msg_type(enum probe_type_e)                   |
        |   |----------------|----------------|----------------|----------------|
        |   |                               msg_len                             |
    ----|---|----------------|----------------|----------------|----------------|
   /    |   |              type(100)          |           len(FIX 4 Bytes)      |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |                      value(probe_range_flags)                     |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |              type(101)          | len(sizeof(struct probe_params))|
   |   FIX  |----------------|----------------|----------------|----------------|
   |    |   |                                                                   |
   |    |   |                                                                   |
   |    |   ~                  value(struct probe_params)                       ~
   |    |   |                                                                   |
msg_len |   |                                                                   |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |              type(102)          |           len(FIX 4 Bytes)      |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |                          value(probe_flags)                       |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |              type(103)          |           len(FIX 4 Bytes)      |
   |    |   |----------------|----------------|----------------|----------------|
   |    \   |                         value(snooper_num)                        |
   |     ---|----------------|----------------|----------------|----------------|
   |    /   |    type(eg:proc,container,db)   |     len(eg:proc,container,db)   |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |                         value(snooper_info)                       |
   | Option |             sub_type            |             sub_len             |
   |    |   ~                                                                   ~
   |    |   |                 sub_value(eg: container_id, db_name...)           |
   \    \   |                                                                   |
    ----|---|----------------|----------------|----------------|----------------|
*/

static void __free_container_obj(struct snooper_con_info_s *container)
{
    if (container->con_id) {
        (void)free(container->con_id);
        container->con_id = NULL;
    }
    if (container->container_name) {
        (void)free(container->container_name);
        container->container_name = NULL;
    }
    if (container->libc_path) {
        (void)free(container->libc_path);
        container->libc_path = NULL;
    }
    if (container->libssl_path) {
        (void)free(container->libssl_path);
        container->libssl_path = NULL;
    }
    if (container->pod_id) {
        (void)free(container->pod_id);
        container->pod_id = NULL;
    }
    if (container->pod_ip_str) {
        (void)free(container->pod_ip_str);
        container->pod_ip_str = NULL;
    }
    return;
}

static void __free_gaussdb_obj(struct snooper_gaussdb_s *gaussdb)
{
    if (gaussdb->ip) {
        (void)free(gaussdb->ip);
        gaussdb->ip = NULL;
    }
    if (gaussdb->dbname) {
        (void)free(gaussdb->dbname);
        gaussdb->dbname = NULL;
    }
    if (gaussdb->usr) {
        (void)free(gaussdb->usr);
        gaussdb->usr = NULL;
    }
    if (gaussdb->pass) {
        (void)free(gaussdb->pass);
        gaussdb->pass = NULL;
    }
    return;
}

static u32 get_tlv_len_proc(struct snooper_obj_s *obj)
{
    if (obj->type != SNOOPER_OBJ_PROC) {
        return 0;
    }
    return sizeof(struct ipc_tlv_s) + sizeof(u32);
}

static u32 get_tlv_len_container(struct snooper_obj_s *obj)
{
    struct snooper_con_info_s *container;
    u32 tlv_len = sizeof(struct ipc_tlv_s);

    if (obj->type != SNOOPER_OBJ_CON) {
        return 0;
    }

    tlv_len += sizeof(u32) + sizeof(u32); // flags and cpucg_inode

    container = &(obj->obj.con_info);
    if (container->con_id) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(container->con_id) + 1;
    }
    if (container->container_name) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(container->container_name) + 1;
    }
    if (container->libc_path) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(container->libc_path) + 1;
    }
    if (container->libssl_path) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(container->libssl_path) + 1;
    }
    if (container->pod_id) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(container->pod_id) + 1;
    }
    if (container->pod_ip_str) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(container->pod_ip_str) + 1;
    }

    return tlv_len;
}

static u32 get_tlv_len_gaussdb(struct snooper_obj_s *obj)
{
    struct snooper_gaussdb_s *gaussdb;
    u32 tlv_len = sizeof(struct ipc_tlv_s);

    if (obj->type != SNOOPER_OBJ_GAUSSDB) {
        return 0;
    }

    tlv_len += sizeof(u32); // port

    gaussdb = &(obj->obj.gaussdb);
    if (gaussdb->ip) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(gaussdb->ip) + 1;
    }
    if (gaussdb->dbname) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(gaussdb->dbname) + 1;
    }
    if (gaussdb->usr) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(gaussdb->usr) + 1;
    }
    if (gaussdb->pass) {
        tlv_len += sizeof(struct ipc_tlv_s) + strlen(gaussdb->pass) + 1;
    }

    return tlv_len;
}

static int build_tlv_proc(char *buf, size_t size, struct snooper_obj_s *obj)
{
    u32 *proc_id;
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;
    if (obj->type != SNOOPER_OBJ_PROC) {
        return -1;
    }

    if (size < sizeof(u32) + sizeof(struct ipc_tlv_s)) {
        return -1;
    }

    tlv->type = SNOOPER_OBJ_PROC;
    tlv->len = sizeof(u32);
    proc_id = (u32 *)(tlv + 1);
    *proc_id = obj->obj.proc.proc_id;
    return tlv->len + sizeof(struct ipc_tlv_s);
}

static int build_tlv_container(char *buf, size_t size, struct snooper_obj_s *obj)
{
    int max_len = (int)size;
    u32 tlv_len_1st = 0, tlv_len_2nd = 0;
    char *p, *start;
    struct snooper_con_info_s *container;
    struct ipc_tlv_s *tlv_1st, *tlv_2nd;
    if (obj->type != SNOOPER_OBJ_CON) {
        return -1;
    }

    tlv_1st = (struct ipc_tlv_s *)buf;
    tlv_1st->type = SNOOPER_OBJ_CON;
    container = &(obj->obj.con_info);
    start = (char *)(tlv_1st + 1);

    p = start + tlv_len_1st;
    *(u32 *)p = container->flags;
    tlv_len_1st += sizeof(u32);
    max_len -= tlv_len_1st;

    p = start + tlv_len_1st;
    *(u32 *)p = container->cpucg_inode;
    tlv_len_1st += sizeof(u32);
    max_len -= tlv_len_1st;

    if (container->con_id) {
        tlv_len_2nd = strlen(container->con_id) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_CONTAINER_ID;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, container->con_id, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (container->container_name) {
        tlv_len_2nd = strlen(container->container_name) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_CONTAINER_NAME;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, container->container_name, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (container->libc_path) {
        tlv_len_2nd = strlen(container->libc_path) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_LIBC_PATH;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, container->libc_path, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (container->libssl_path) {
        tlv_len_2nd = strlen(container->libssl_path) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }

        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_LIBSSL_PATH;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, container->libssl_path, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (container->pod_id) {
        tlv_len_2nd = strlen(container->pod_id) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_POD_ID;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, container->pod_id, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (container->pod_ip_str) {
        tlv_len_2nd = strlen(container->pod_ip_str) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_POD_IP;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, container->pod_ip_str, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    tlv_1st->len = tlv_len_1st;
    return tlv_1st->len + sizeof(struct ipc_tlv_s);
}

static int build_tlv_gaussdb(char *buf, size_t size, struct snooper_obj_s *obj)
{
    int max_len = (int)size;
    u32 tlv_len_1st = 0, tlv_len_2nd = 0;
    char *p, *start;
    struct snooper_gaussdb_s *gaussdb;
    struct ipc_tlv_s *tlv_1st, *tlv_2nd;
    if (obj->type != SNOOPER_OBJ_GAUSSDB) {
        return -1;
    }

    tlv_1st = (struct ipc_tlv_s *)buf;
    tlv_1st->type = SNOOPER_OBJ_GAUSSDB;
    gaussdb = &(obj->obj.gaussdb);
    start = (char *)(tlv_1st->value);

    p = start + tlv_len_1st;
    *(u32 *)p = gaussdb->port;
    tlv_len_1st += sizeof(u32);
    max_len -= tlv_len_1st;

    if (gaussdb->ip) {
        tlv_len_2nd = strlen(gaussdb->ip) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_GAUSSDB_IP;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, gaussdb->ip, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (gaussdb->dbname) {
        tlv_len_2nd = strlen(gaussdb->dbname) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_GAUSSDB_DBNAME;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, gaussdb->dbname, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (gaussdb->usr) {
        tlv_len_2nd = strlen(gaussdb->usr) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }
        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_GAUSSDB_USR;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, gaussdb->usr, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    if (gaussdb->pass) {
        tlv_len_2nd = strlen(gaussdb->pass) + 1 + sizeof(struct ipc_tlv_s);
        max_len -= tlv_len_2nd;
        if (max_len < 0) {
            return -1;
        }

        p = start + tlv_len_1st;
        tlv_2nd = (struct ipc_tlv_s *)p;
        tlv_2nd->type = IPCT_GAUSSDB_PASS;
        tlv_2nd->len = tlv_len_2nd - sizeof(struct ipc_tlv_s);
        (void)memcpy(tlv_2nd->value, gaussdb->pass, tlv_2nd->len);

        tlv_len_1st += tlv_len_2nd;
    }

    tlv_1st->len = tlv_len_1st;
    return tlv_1st->len + sizeof(struct ipc_tlv_s);
}

static int deserialize_tlv_proc(char *buf, size_t size, struct snooper_obj_s *obj)
{
    struct ipc_tlv_s *tlv;
    if (size < sizeof(struct ipc_tlv_s) + sizeof(u32)) {
        return -1;
    }

    tlv = (struct ipc_tlv_s *)buf;
    if (tlv->len != sizeof(u32) || tlv->type != SNOOPER_OBJ_PROC) {
        return -1;
    }

    obj->type = SNOOPER_OBJ_PROC;
    obj->obj.proc.proc_id = *(u32 *)tlv->value;
    return (sizeof(struct ipc_tlv_s) + sizeof(u32));
}

static int deserialize_tlv_container(char *buf, size_t size, struct snooper_obj_s *obj)
{
    int err = 0;
    size_t offset = 0;
    struct ipc_tlv_s *tlv_1st, *tlv_2nd;
    char *p, *start;
    struct snooper_con_info_s *container;

    tlv_1st = (struct ipc_tlv_s *)buf;
    if (tlv_1st->type != SNOOPER_OBJ_CON) {
        return -1;
    }

    if (tlv_1st->len < (sizeof(u32) + sizeof(u32))) {
        return -1;
    }

    obj->type = SNOOPER_OBJ_CON;
    container = &(obj->obj.con_info);
    start = (char *)(tlv_1st->value);

    p = start + offset;
    container->flags = *(u32 *)p;
    offset += sizeof(u32);

    p = start + offset;
    container->cpucg_inode = *(u32 *)p;
    offset += sizeof(u32);

    if (offset >= size) {
        goto end;
    }

    do {
        p = start + offset;
        tlv_2nd = (struct ipc_tlv_s *)p;
        switch (tlv_2nd->type) {
            case IPCT_CONTAINER_ID:
            {
                container->con_id = (char *)malloc(tlv_2nd->len);
                if (container->con_id == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(container->con_id, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_CONTAINER_NAME:
            {
                container->container_name = (char *)malloc(tlv_2nd->len);
                if (container->container_name == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(container->container_name, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_LIBC_PATH:
            {
                container->libc_path = (char *)malloc(tlv_2nd->len);
                if (container->libc_path == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(container->libc_path, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_LIBSSL_PATH:
            {
                container->libssl_path = (char *)malloc(tlv_2nd->len);
                if (container->libssl_path == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(container->libssl_path, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_POD_ID:
            {
                container->pod_id = (char *)malloc(tlv_2nd->len);
                if (container->pod_id == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(container->pod_id, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_POD_IP:
            {
                container->pod_ip_str = (char *)malloc(tlv_2nd->len);
                if (container->pod_ip_str == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(container->pod_ip_str, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            default:
            {
                err = 1;
                break;
            }
        }
    } while (offset < size);

end:
    if (err) {
        __free_container_obj(container);
        obj->type = SNOOPER_OBJ_MAX;
    }
    return (err) ? -1 : (int)(offset + sizeof(struct ipc_tlv_s));
}

static int deserialize_tlv_gaussdb(char *buf, size_t size, struct snooper_obj_s *obj)
{
    int err = 0;
    size_t offset = 0;
    struct ipc_tlv_s *tlv_1st, *tlv_2nd;
    char *p, *start;
    struct snooper_gaussdb_s *gaussdb;

    tlv_1st = (struct ipc_tlv_s *)buf;
    if (tlv_1st->type != SNOOPER_OBJ_GAUSSDB) {
        return -1;
    }

    if (tlv_1st->len < sizeof(u32)) {
        return -1;
    }

    obj->type = SNOOPER_OBJ_GAUSSDB;
    gaussdb = &(obj->obj.gaussdb);
    start = (char *)(tlv_1st->value);

    p = start + offset;
    gaussdb->port = *(u32 *)p;
    offset += sizeof(u32);

    if (offset >= size) {
        goto end;
    }

    do {
        p = start + offset;
        tlv_2nd = (struct ipc_tlv_s *)p;
        switch (tlv_2nd->type) {
            case IPCT_GAUSSDB_IP:
            {
                gaussdb->ip = (char *)malloc(tlv_2nd->len);
                if (gaussdb->ip == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(gaussdb->ip, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_GAUSSDB_DBNAME:
            {
                gaussdb->dbname = (char *)malloc(tlv_2nd->len);
                if (gaussdb->dbname == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(gaussdb->dbname, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_GAUSSDB_USR:
            {
                gaussdb->usr = (char *)malloc(tlv_2nd->len);
                if (gaussdb->usr == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(gaussdb->usr, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            case IPCT_GAUSSDB_PASS:
            {
                gaussdb->pass = (char *)malloc(tlv_2nd->len);
                if (gaussdb->pass == NULL) {
                    err = 1;
                    goto end;
                }

                (void)memcpy(gaussdb->pass, tlv_2nd->value, tlv_2nd->len);
                offset += tlv_2nd->len + sizeof(struct ipc_tlv_s);
                break;
            }
            default:
            {
                err = 1;
                break;
            }
        }
    } while (offset < size);

end:
    if (err) {
        __free_gaussdb_obj(gaussdb);
        obj->type = SNOOPER_OBJ_MAX;
    }
    return (err) ? -1 : (int)(offset + sizeof(struct ipc_tlv_s));
}

typedef u32 (*GetTlvLen)(struct snooper_obj_s *);
typedef int (*BuildTlv)(char *, size_t, struct snooper_obj_s *);
typedef int (*DeserializeTlv)(char *, size_t, struct snooper_obj_s *);

struct ipc_operator_s {
    enum snooper_obj_e type;
    GetTlvLen get_tlv_len;
    BuildTlv build_tlv;
    DeserializeTlv deserialize_tlv;
};

static struct ipc_operator_s ipc_operators[SNOOPER_OBJ_MAX] = {
    {SNOOPER_OBJ_PROC,      get_tlv_len_proc,       build_tlv_proc,         deserialize_tlv_proc},
    {SNOOPER_OBJ_CON,       get_tlv_len_container,  build_tlv_container,    deserialize_tlv_container},
    {SNOOPER_OBJ_GAUSSDB,   get_tlv_len_gaussdb,    build_tlv_gaussdb,      deserialize_tlv_gaussdb}
};

static u32 __calc_ipc_msg_len(struct ipc_body_s* ipc_body)
{
    u32 msg_len = IPC_TLV_LEN_DEFAULT;

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        msg_len += ipc_operators[ipc_body->snooper_objs[i].type].get_tlv_len(&(ipc_body->snooper_objs[i]));
    }
    return msg_len;
}

static int __build_probe_range_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    u32 *value;
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    tlv->type = IPCT_PROBE_RANGE;
    tlv->len = sizeof(u32);
    value = (u32 *)(buf + sizeof(struct ipc_tlv_s));
    *value = ipc_body->probe_range_flags;
    return (sizeof(struct ipc_tlv_s) + sizeof(u32));
}

#if 0
static int __build_probe_flags_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    u32 *value;
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    tlv->type = IPCT_PROBE_FLAGS;
    tlv->len = sizeof(u32);
    value = (u32 *)(buf + sizeof(struct ipc_tlv_s));
    *value = ipc_body->probe_flags;
    return (sizeof(struct ipc_tlv_s) + sizeof(u32));
}
#endif

static int __build_snooper_num_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    u32 *value;
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    tlv->type = IPCT_SNOOPER_NUM;
    tlv->len = sizeof(u32);
    value = (u32 *)(buf + sizeof(struct ipc_tlv_s));
    *value = ipc_body->snooper_obj_num;
    return (sizeof(struct ipc_tlv_s) + sizeof(u32));
}

static int __build_probe_params_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    struct probe_params *value;
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    tlv->type = IPCT_PROBE_PARAMS;
    tlv->len = sizeof(struct probe_params);
    value = (struct probe_params *)(buf + sizeof(struct ipc_tlv_s));
    (void)memcpy(value, &(ipc_body->probe_param), sizeof(struct probe_params));
    return (sizeof(struct ipc_tlv_s) + sizeof(struct probe_params));
}

static int __build_snooper_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    int max_len = (int)size;
    char *cur = buf;
    int build_len, fill_len = 0;

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        build_len = ipc_operators[ipc_body->snooper_objs[i].type].build_tlv(cur,
            (size_t)max_len, &(ipc_body->snooper_objs[i]));
        if (build_len < 0) {
            return -1;
        }
        max_len = max_len - build_len;
        if (max_len < 0) {
            return -1;
        }
        cur += build_len;
        fill_len += build_len;
    }

    return fill_len;
}

static int __build_ipc_msg(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    int fill_len = 0, build_len = 0;
    int max_len = (int)size;
    char *cur = buf;

    build_len = __build_probe_range_tlv(cur, (size_t)max_len, ipc_body);
    max_len = max_len - build_len;
    if (max_len <= 0) {
        return -1;
    }
    cur += build_len;
    fill_len += build_len;

    build_len = __build_probe_params_tlv(cur, (size_t)max_len, ipc_body);
    max_len = max_len - build_len;
    if (max_len <= 0) {
        return -1;
    }
    cur += build_len;
    fill_len += build_len;

#if 0
    build_len = __build_probe_flags_tlv(cur, (size_t)max_len, ipc_body);
    max_len = max_len - build_len;
    if (max_len <= 0) {
        return -1;
    }
    cur += build_len;
    fill_len += build_len;
#endif

    build_len = __build_snooper_num_tlv(cur, (size_t)max_len, ipc_body);
    max_len = max_len - build_len;
    if (max_len < 0) {  // snooper_num为0的情况，此时max_len==0
        return -1;
    }
    cur += build_len;
    fill_len += build_len;

    build_len = __build_snooper_tlv(cur, (size_t)max_len, ipc_body);
    if (build_len < 0) {
        return -1;
    }
    fill_len += build_len;
    if ((size_t)fill_len != size) {
        return -1;
    }
    return 0;
}

static void __free_ipc_msg(struct ipc_msg_s* ipc_msg)
{
    (void)free(ipc_msg);
}

static struct ipc_msg_s* __malloc_ipc_msg(struct ipc_body_s* ipc_body, long msg_type)
{
    size_t size;
    struct ipc_msg_s* ipc_msg;

    u32 msg_len = __calc_ipc_msg_len(ipc_body);

    size = sizeof(struct ipc_msg_s) + msg_len;
    ipc_msg = (struct ipc_msg_s *)malloc(size);
    if (ipc_msg == NULL) {
        return NULL;
    }

    (void)memset(ipc_msg, 0, size);
    ipc_msg->msg_type = msg_type;
    ipc_msg->msg_len = msg_len;
    return ipc_msg;
}

static struct ipc_msg_s* __create_ipc_msg(struct ipc_body_s* ipc_body, long msg_type)
{
    int ret;
    char *buf;
    struct ipc_msg_s* ipc_msg = __malloc_ipc_msg(ipc_body, msg_type);
    if (ipc_msg == NULL) {
        return NULL;
    }

    ipc_msg->msg_flag = ipc_body->probe_flags;
    buf = (char *)(ipc_msg->msg);

    ret = __build_ipc_msg(buf, ipc_msg->msg_len, ipc_body);
    if (ret) {
        __free_ipc_msg(ipc_msg);
        return NULL;
    }

    return ipc_msg;
}

#define __GOPHER_IPC_MSG_LEN  (4 * 1024)
static char g_rcv_ipc_msg_buffer[__GOPHER_IPC_MSG_LEN + sizeof(struct ipc_msg_s)];
static struct ipc_msg_s* __get_raw_ipc_msg(long msg_type)
{
    struct ipc_msg_s *ipc_msg;
    struct ipc_tlv_s *tlv;

    ipc_msg = (struct ipc_msg_s *)g_rcv_ipc_msg_buffer;

    ipc_msg->msg_type = msg_type;
    ipc_msg->msg_len = __GOPHER_IPC_MSG_LEN;

    tlv = (struct ipc_tlv_s *)ipc_msg->msg;
    tlv->type = SNOOPER_OBJ_MAX;    // Initialize, Setting invalid value.
    tlv->len = 0;

    return ipc_msg;
}

static int __deserialize_probe_range_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    if ((tlv->type != IPCT_PROBE_RANGE) || (tlv->len != sizeof(u32))) {
        return -1;
    }

    ipc_body->probe_range_flags = *(u32 *)tlv->value;
    return (tlv->len + sizeof(struct ipc_tlv_s));
}

static int __deserialize_probe_params_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    if ((tlv->type != IPCT_PROBE_PARAMS) || (tlv->len != sizeof(struct probe_params))) {
        return -1;
    }

    (void)memcpy(&(ipc_body->probe_param), tlv->value, sizeof(struct probe_params));
    return (tlv->len + sizeof(struct ipc_tlv_s));
}

#if 0
static int __deserialize_probe_flags_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    if ((tlv->type != IPCT_PROBE_FLAGS) || (tlv->len != sizeof(u32))) {
        return -1;
    }

    ipc_body->probe_flags = *(u32 *)tlv->value;
    return (tlv->len + sizeof(struct ipc_tlv_s));
}
#endif

static int __deserialize_snooper_num_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    struct ipc_tlv_s *tlv = (struct ipc_tlv_s *)buf;

    if ((tlv->type != IPCT_SNOOPER_NUM) || (tlv->len != sizeof(u32))) {
        return -1;
    }

    ipc_body->snooper_obj_num = *(u32 *)tlv->value;
    return (tlv->len + sizeof(struct ipc_tlv_s));
}

static int __deserialize_snooper_tlv(char *buf, size_t size, struct ipc_body_s* ipc_body)
{
    int max_len = (int)size, offset_len = 0, deserialize_len = 0;
    char *start = buf, *cur;
    struct ipc_tlv_s *tlv;
    int snooper_index = 0;
    struct snooper_obj_s *snooper_obj;

    do {
        cur  = start + offset_len;

        tlv = (struct ipc_tlv_s *)cur;
        if (tlv->type >= SNOOPER_OBJ_MAX) {
            return -1;
        }

        if (snooper_index >= SNOOPER_MAX) {
            return -1;
        }

        if (ipc_operators[tlv->type].deserialize_tlv == NULL) {
            return -1;
        }
        snooper_obj = &(ipc_body->snooper_objs[snooper_index]);
        deserialize_len = ipc_operators[tlv->type].deserialize_tlv(cur, (size_t)max_len, snooper_obj);
        if (deserialize_len < 0) {
            return -1;
        }
        offset_len += deserialize_len;
        max_len -= deserialize_len;
        snooper_index++;
    } while (max_len > 0);

    return (size_t)offset_len;
}

static int __deserialize_ipc_msg(struct ipc_msg_s* ipc_msg, struct ipc_body_s* ipc_body)
{
    char *cur, *start;
    int max_len = ipc_msg->msg_len, offset = 0, deserialize_len = 0;

    start = ipc_msg->msg;

    cur = start + offset;
    deserialize_len = __deserialize_probe_range_tlv(cur, (size_t)max_len, ipc_body);
    if (deserialize_len < 0) {
        return -1;
    }
    offset += deserialize_len;
    max_len -= deserialize_len;
    if (max_len < 0) {
        return -1;
    }

    cur = start + offset;
    deserialize_len = __deserialize_probe_params_tlv(cur, (size_t)max_len, ipc_body);
    if (deserialize_len < 0) {
        return -1;
    }
    offset += deserialize_len;
    max_len -= deserialize_len;
    if (max_len < 0) {
        return -1;
    }

#if 0
    cur = start + offset;
    deserialize_len = __deserialize_probe_flags_tlv(cur, (size_t)max_len, ipc_body);
    if (deserialize_len < 0) {
        return -1;
    }
    offset += deserialize_len;
    max_len -= deserialize_len;
    if (max_len < 0) {
        return -1;
    }
#endif

    cur = start + offset;
    deserialize_len = __deserialize_snooper_num_tlv(cur, (size_t)max_len, ipc_body);
    if (deserialize_len < 0) {
        return -1;
    }
    offset += deserialize_len;
    max_len -= deserialize_len;
    if (max_len < 0) {
        return -1;
    }

    if (max_len == 0) {
        return offset;
    }

    cur = start + offset;
    deserialize_len = __deserialize_snooper_tlv(cur, (size_t)max_len, ipc_body);
    if (deserialize_len < 0) {
        return -1;
    }
    offset += deserialize_len;
    max_len -= deserialize_len;
    if (max_len < 0) {
        return -1;
    }
    return offset;
}

#define __GOPHER_BIN_FILE     "/usr/bin/gala-gopher"
#define __GOPHER_PROJECT_ID   'g'     // used by ftok to generate unique msg queue key
#define __GOPHER_MSQ_PERM     0600
int create_ipc_msg_queue(int ipc_flag)
{
    int msqid;
    key_t key;

    if ((key = ftok(__GOPHER_BIN_FILE, __GOPHER_PROJECT_ID)) < 0) {
        ERROR("[IPC] ftok to generate IPC message key failed\n");
        return -1;
    }

    msqid = msgget(key, __GOPHER_MSQ_PERM | IPC_EXCL);
    if (ipc_flag & IPC_CREAT) {
        /* In case of main process aborted abnormally, clean up old msg queue */
        destroy_ipc_msg_queue(msqid);
        if ((msqid = msgget(key, __GOPHER_MSQ_PERM | ipc_flag)) == -1) {
            ERROR("[IPC] Create IPC message queue(ipc_flags = %d) failed.\n", ipc_flag);
            return -1;
        }
        return msqid;
    }

    if (msqid < 0) {
        ERROR("[IPC] Get IPC message queue(ipc_flags = %d) failed.\n", ipc_flag);
        return -1;
    }

    return msqid;
}

void destroy_ipc_msg_queue(int msqid)
{
    if (msqid < 0) {
        return;
    }

    (void)msgctl(msqid, IPC_RMID, NULL);
}

int send_ipc_msg(int msqid, long msg_type, struct ipc_body_s* ipc_body)
{
    int err = 0;
    struct ipc_msg_s* ipc_msg;

    if (msqid < 0) {
        return -1;
    }

    if (msg_type < PROBE_BASEINFO || msg_type >= PROBE_TYPE_MAX) {
        return -1;
    }

    ipc_msg = __create_ipc_msg(ipc_body, msg_type);
    if (ipc_msg == NULL) {
        return -1;
    }

    if (msgsnd(msqid, ipc_msg, ipc_msg->msg_len + sizeof(ipc_msg->msg_len) + sizeof(ipc_msg->msg_flag), 0) < 0) {
        ERROR("[IPC] send ipc message(msg_type = %ld) failed(%d).\n", msg_type, errno);
        err = -1;
    }

    __free_ipc_msg(ipc_msg);
    ipc_msg = NULL;

    return err;
}

/* return 0 when ipc msg recvd and build a valid ipc_body */
int recv_ipc_msg(int msqid, long msg_type, struct ipc_body_s *ipc_body)
{
    int err = -1;
    int deserialize_len;
    struct ipc_msg_s* ipc_msg;
    int msg_rcvd = 0;
    u32 msg_len;
    u32 msg_flags = 0;

    if (msqid < 0) {
        return -1;
    }

    ipc_msg = __get_raw_ipc_msg(msg_type);
    msg_len = ipc_msg->msg_len + sizeof(ipc_msg->msg_len) + sizeof(ipc_msg->msg_flag);
    /* Only deal with the last message within every check */
    while (msgrcv(msqid, ipc_msg, msg_len, msg_type, IPC_NOWAIT) != -1) {
        msg_rcvd = 1;
        msg_flags |= ipc_msg->msg_flag;
    }

    if (msg_rcvd) {
        if (ipc_msg->msg_len > __GOPHER_IPC_MSG_LEN) {
            ERROR("[IPC] recv ipc message(msg_type = %d) invalid len.\n", msg_type);
            goto end;
        }
        (void)memset(ipc_body, 0, sizeof(struct ipc_body_s));
        deserialize_len = __deserialize_ipc_msg(ipc_msg, ipc_body);
        if (deserialize_len < 0) {
            ERROR("[IPC] recv ipc message(msg_type = %d) deserialize failed.\n", msg_type);
            goto end;
        }
        ipc_body->probe_flags = msg_flags;
        err = 0;
    }

end:
    if (err && msg_rcvd) {
        destroy_ipc_body(ipc_body);
    }
    return err;
}

void clear_ipc_msg(long msg_type)
{
    int msqid;
    struct ipc_msg_s *ipc_msg;
    u32 msg_len;

    msqid = create_ipc_msg_queue(IPC_EXCL);
    if (msqid < 0) {
        return;
    }

    ipc_msg = __get_raw_ipc_msg(msg_type);
    msg_len = ipc_msg->msg_len + sizeof(u32);
    while (1) {
        if (msgrcv(msqid, ipc_msg, msg_len, msg_type, IPC_NOWAIT) == -1) {
            break;
        }
    }
}

void destroy_ipc_body(struct ipc_body_s *ipc_body)
{
    struct snooper_con_info_s *container;
    struct snooper_gaussdb_s *gaussdb;

    if (ipc_body == NULL) {
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        switch (ipc_body->snooper_objs[i].type) {
            case SNOOPER_OBJ_CON:
            {
                container = &(ipc_body->snooper_objs[i].obj.con_info);
                __free_container_obj(container);
                break;
            }
            case SNOOPER_OBJ_GAUSSDB:
            {
                gaussdb = &(ipc_body->snooper_objs[i].obj.gaussdb);
                __free_gaussdb_obj(gaussdb);
                break;
            }
            default:
            {
                break;
            }
        }
    }
    ipc_body->snooper_obj_num = 0;
    ipc_body->probe_range_flags = 0;
    ipc_body->probe_flags = 0;
    return;
}

