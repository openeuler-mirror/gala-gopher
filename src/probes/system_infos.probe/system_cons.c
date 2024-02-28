/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wo_cow
 * Create: 2024-02-28
 * Description: system con probe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include "common.h"
#include "container.h"
#include "nprobe_fprintf.h"
#include "system_cons.h"

#define METRICS_CON_IO_NAME "system_con_io"
#define PROC_DIR_IO         "du -sb %s/%s 2> /dev/null"

static con_hash_t *g_conmap = NULL;
static u64 g_proc_write_bytes_to_dir;        // FROM 'du -sb /proc/<pid>/root/<dir>'

static void hash_add_con(con_hash_t *one_con)
{
    HASH_ADD(hh, g_conmap, con_id, sizeof(const char *), one_con);
    return;
}

static con_hash_t *hash_find_con(const char *con_id)
{
    con_hash_t *p = NULL;
    con_hash_t temp = {0};

    HASH_FIND(hh, g_conmap, &con_id, sizeof(con_id), p);

    return p;
}

static void hash_clear_all_con(void)
{
    if (g_conmap == NULL) {
        return;
    }
    con_hash_t *r, *tmp;
    HASH_ITER(hh, g_conmap, r, tmp) {
        HASH_DEL(g_conmap, r);
        if (r != NULL) {
            (void)free(r);
        }
    }
}

static int update_con_infos(const char *cmd, u64 *proc_write_bytes_to_dir)
{
    int ret = 0;
    FILE *f = NULL;
    u64 value = 0;
    char line[LINE_BUF_LEN];

    g_proc_write_bytes_to_dir = *proc_write_bytes_to_dir;
    if (cmd[0] == 0) {
        return 0;
    }

    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }

    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        goto out;
    }

    value = 0;
    if (sscanf(line, "%llu %*s", &value) < 1) {
        goto out;
    }

    *proc_write_bytes_to_dir = value;

out:
    (void)pclose(f);
    return 0;

}

static void output_con_io_infos(con_hash_t *one_con, const char *dir, unsigned int period)
{
    nprobe_fprintf(stdout,
        "|%s|%s|%s|%llu|\n",
        METRICS_CON_IO_NAME,
        one_con->con_id,
        dir,
        (one_con->proc_write_bytes_to_dir - g_proc_write_bytes_to_dir) / period);
    return;
}

static con_hash_t* init_one_con(const char *con_id, char *dir_str)
{
    int ret;
    con_hash_t *item;
    char container_root[PATH_LEN];

    item = (con_hash_t *)malloc(sizeof(con_hash_t));
    (void)memset(item, 0, sizeof(con_hash_t));

    container_root[0] = 0;
    ret = get_container_merged_path((const char *)con_id, container_root, PATH_LEN);
    if (ret != 0) {
        free(item);
        return NULL;
    }

    item->con_id = con_id;
    item->flag = CON_IN_PROBE_RANGE;

    (void)snprintf(item->cmd, sizeof(item->cmd), PROC_DIR_IO, container_root, dir_str);

    (void)update_con_infos(item->cmd, &item->proc_write_bytes_to_dir);

    return item;
}

int system_con_probe(struct ipc_body_s *ipc_body)
{
    con_hash_t *con, *tmp;

    HASH_ITER(hh, g_conmap, con, tmp) {
        if (con->flag == CON_IN_PROBE_RANGE) {
            (void)update_con_infos(con->cmd, &con->proc_write_bytes_to_dir);
            output_con_io_infos(con, ipc_body->probe_param.elf_path, ipc_body->probe_param.period);
        }
    }

    return 0;
}

int refresh_con_filter_map(struct ipc_body_s *ipc_body)
{
    struct snooper_con_info_s *container;
    con_hash_t *item, *p;

    hash_clear_all_con();

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type != SNOOPER_OBJ_CON) {
            continue;
        }
    
        container = &(ipc_body->snooper_objs[i].obj.con_info);
        p = hash_find_con((const char *)container->con_id);
        if (p == NULL) {
            item = init_one_con((const char *)container->con_id, ipc_body->probe_param.svg_dir);
            if (item == NULL) {
                ERROR("[SYSTEM_PROBE] init container(%s) failed\n", container->con_id);
                continue;
            }
            hash_add_con(item);
        }
    }
    return 0;
}

