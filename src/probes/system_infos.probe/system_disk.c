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
 * Author: dowzyx
 * Create: 2022-03-01
 * Description: system disk probe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "event.h"
#include "nprobe_fprintf.h"
#include "system_disk.h"

#define METRICS_DF_NAME         "system_df"
#define METRICS_IOSTAT_NAME     "system_iostat"
#define ENTITY_FS_NAME          "fs"
#define ENTITY_DISK_NAME        "disk"
#define SYSTEM_INODE_COMMAND    "/usr/bin/df -T -i"
#define SYSTEM_BLOCK_CMD        "/usr/bin/df -T"
#define SYSTEM_MOUNT_STAT_CMD   "cat /proc/mounts"
#define SYSTEM_DISKSTATS        "/proc/diskstats"
#define SYSTEM_DISKSTATS_CMD    "/usr/bin/cat /proc/diskstats"
#define SYSTEM_DISK_DEV_NUM     "/usr/bin/cat /proc/diskstats | wc -l"

static df_stats *g_df_tbl = NULL;

#define DF_INODE_FIELD_NUM 7
static int get_df_inode_fields(char *line, df_stats *stats)
{
    int ret;

    ret = sscanf(line, "%s %s %ld %ld %ld %ld%*s %s",
        &stats->fsname, &stats->fstype, &stats->inode_sum, &stats->inode_used,
        &stats->inode_free, &stats->inode_used_per, &stats->mount_on);
    if (ret < DF_INODE_FIELD_NUM) {
        DEBUG("[SYSTEM_DISK] get df stats fields fail.\n");
        return -1;
    }
    return 0;
}

#define DF_BLOCK_FIELD_NUM 5
static int get_df_block_fields(char *line, df_stats *stats)
{
    int ret;

    ret = sscanf(line, "%*s %*s %ld %ld %ld %ld%*s %s",
        &stats->blk_sum, &stats->blk_used,
        &stats->blk_free, &stats->blk_used_per, &stats->mount_on);
    if (ret < DF_BLOCK_FIELD_NUM) {
        DEBUG("[SYSTEM_DISK] get df stats fields fail.\n");
        return -1;
    }
    return 0;
}

#define MNT_FIELD_NUM 2
static int get_fs_mount_status(char *line, char mountOn[MOUNTON_LEN], char mountStatus[MOUNTSTATUS_LEN])
{
    int ret;
    char buf[LINE_BUF_LEN];
    char *firstComma;

    buf[0] = 0;
    ret = sscanf(line, "%*s %s %*s %s", mountOn, buf);
    if (ret < MNT_FIELD_NUM) {
        DEBUG("[SYSTEM_DISK] get fs mount status fail.\n");
        return -1;
    }

    firstComma = strchr(buf, ',');
    if (!firstComma) {
        DEBUG("[SYSTEM_DISK] get fs mount status fail.\n");
        return -1;
    }
    *firstComma = '\0';
    (void)snprintf(mountStatus, MOUNTSTATUS_LEN, "%s", buf);
    return 0;
}

static void report_disk_status(df_stats *fsItem, struct ipc_body_s *ipc_body)
{
    char entityid[LINE_BUF_LEN];
    struct event_info_s evt = {0};

    if (ipc_body->probe_param.logs == 0) {
        return;
    }

    entityid[0] = 0;

    if (ipc_body->probe_param.res_percent_upper > 0 &&
        fsItem->inode_used_per > ipc_body->probe_param.res_percent_upper) {
        (void)snprintf(entityid, sizeof(entityid), "%s", fsItem->mount_on);
        evt.entityName = ENTITY_FS_NAME;
        evt.entityId = entityid;
        evt.metrics = "IUsePer";

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Too many Inodes consumed(%d%%).",
                    fsItem->inode_used_per);
    }
    if (ipc_body->probe_param.res_percent_upper > 0 &&
        fsItem->blk_used_per > ipc_body->probe_param.res_percent_upper) {
        if (entityid[0] == 0) {
            (void)snprintf(entityid, sizeof(entityid), "%s", fsItem->mount_on);
        }
        evt.entityName = ENTITY_FS_NAME;
        evt.entityId = entityid;
        evt.metrics = "UsePer";
        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Too many Blocks used(%d%%).",
                    fsItem->blk_used_per);
    }
}

static int init_fs_inode_info(void)
{
    FILE *f = NULL;
    char line[LINE_BUF_LEN];
    int is_first_line = 1;
    df_stats *fsItem;
    df_stats stats;

    f = popen_chroot(SYSTEM_INODE_COMMAND, "r");
    if (f == NULL) {
        return -1;
    }

    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        if (is_first_line) {
            is_first_line = 0;
            continue;
        }
        SPLIT_NEWLINE_SYMBOL(line);

        if (get_df_inode_fields(line, &stats)) {
            continue;
        }

        fsItem = NULL;
        HASH_FIND_STR(g_df_tbl, stats.mount_on, fsItem);
        if (!fsItem) {
            fsItem = (df_stats *)calloc(1, sizeof(df_stats));
            if (!fsItem) {
                DEBUG("[SYSTEM_DISK] failed to malloc memory.\n");
                (void)pclose(f);
                return -1;
            }
            strcpy(fsItem->mount_on, stats.mount_on);
            HASH_ADD_STR(g_df_tbl, mount_on, fsItem);
        }
        fsItem->valid = 1;
        strcpy(fsItem->fsname, stats.fsname);
        strcpy(fsItem->fstype, stats.fstype);
        fsItem->inode_sum = stats.inode_sum;
        fsItem->inode_used = stats.inode_used;
        fsItem->inode_free = stats.inode_free;
        fsItem->inode_used_per = stats.inode_used_per;
        fsItem->blk_sum = 0;
        fsItem->blk_used = 0;
        fsItem->blk_free = 0;
        fsItem->blk_used_per = 0;
        fsItem->mount_status[0] = 0;
    }

    (void)pclose(f);
    return 0;
}

static int init_fs_block_info(void)
{
    FILE *f = NULL;
    char line[LINE_BUF_LEN];
    int is_first_line = 1;
    df_stats *fsItem;
    df_stats stats;

    f = popen_chroot(SYSTEM_BLOCK_CMD, "r");
    if (f == NULL) {
        return -1;
    }

    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        if (is_first_line) {
            is_first_line = 0;
            continue;
        }
        SPLIT_NEWLINE_SYMBOL(line);

        if (get_df_block_fields(line, &stats)) {
            continue;
        }

        fsItem = NULL;
        HASH_FIND_STR(g_df_tbl, stats.mount_on, fsItem);
        if (!fsItem || !fsItem->valid) {
            continue;
        }
        fsItem->blk_sum = stats.blk_sum;
        fsItem->blk_used = stats.blk_used;
        fsItem->blk_free = stats.blk_free;
        fsItem->blk_used_per = stats.blk_used_per;
    }

    (void)pclose(f);
    return 0;

}

static int init_fs_status(void)
{
    FILE *f = NULL;
    df_stats *fsItem;
    char line[LINE_BUF_LEN];
    char mountOn[MOUNTON_LEN];
    char mountStatus[MOUNTSTATUS_LEN];

    f = popen(SYSTEM_MOUNT_STAT_CMD, "r");
    if (f == NULL) {
        return -1;
    }

    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        SPLIT_NEWLINE_SYMBOL(line);

        mountOn[0] = 0;
        mountStatus[0] = 0;
        if (get_fs_mount_status(line, mountOn, mountStatus)) {
            continue;
        }

        fsItem = NULL;
        HASH_FIND_STR(g_df_tbl, mountOn, fsItem);
        if (!fsItem || !fsItem->valid) {
            continue;
        }
        (void)strcpy(fsItem->mount_status, mountStatus);
    }

    (void)pclose(f);
    return 0;

}

int system_disk_probe(struct ipc_body_s *ipc_body)
{
    df_stats *fsItem, *tmp;
    int ret;

    ret = init_fs_inode_info();
    if (ret) {
        return -1;
    }
    ret = init_fs_block_info();
    if (ret) {
        return -1;
    }
    ret = init_fs_status();
    if (ret) {
        return -1;
    }

    HASH_ITER(hh, g_df_tbl, fsItem, tmp) {
        if (!fsItem->valid) {
            HASH_DEL(g_df_tbl, fsItem);
            free(fsItem);
            continue;
        }

        /* output metric */
        (void)nprobe_fprintf(stdout, "|%s|%s|%s|%s|%s|%ld|%ld|%ld|%ld|%ld|%ld|%ld|%ld|\n",
            METRICS_DF_NAME,
            fsItem->mount_on,
            fsItem->mount_status,
            fsItem->fsname,
            fsItem->fstype,
            fsItem->inode_sum,
            fsItem->inode_used,
            fsItem->inode_free,
            fsItem->inode_used_per,
            fsItem->blk_sum,
            fsItem->blk_used,
            fsItem->blk_free,
            fsItem->blk_used_per);
        /* output event */
        report_disk_status(fsItem, ipc_body);
        fsItem->valid = 0;
    }

    return 0;
}

#define DISKSTAT_FIELD_NUM      9
static int get_diskstats_fields(const char *line, disk_stats *stats)
{
    int ret;

    ret = sscanf(line,
        "%*Lu %*Lu %s %lu %*Lu %lu %u %lu %*Lu %lu %u %*Lu %u %u %*Lu %*Lu %*Lu %*Lu",
        &stats->disk_name, &stats->rd_ios, &stats->rd_sectors, &stats->rd_ticks,
        &stats->wr_ios, &stats->wr_sectors, &stats->wr_ticks, &stats->io_ticks, &stats->time_in_queue);
    if (ret < DISKSTAT_FIELD_NUM) {
        DEBUG("[SYSTEM_DISK] get disk stats fields fail.\n");
        return -1;
    }
    return 0;
}

static void cal_disk_io_stats(disk_stats *last, disk_stats *cur, disk_io_stats *io_info, const int period)
{
    if (cur->rd_ios - last->rd_ios == 0) {
        io_info->rd_await = 0.0;
        io_info->rareq_sz = 0.0;
    } else {
        io_info->rd_await = (cur->rd_ticks - last->rd_ticks) / ((double)(cur->rd_ios - last->rd_ios));
        io_info->rareq_sz = (cur->rd_sectors - last->rd_sectors) / ((double)(cur->rd_ios - last->rd_ios)) / 2;
    }
    if (cur->wr_ios - last->wr_ios == 0) {
        io_info->wr_await = 0.0;
        io_info->wareq_sz = 0.0;
    } else {
        io_info->wr_await = (cur->wr_ticks - last->wr_ticks) / ((double)(cur->wr_ios - last->wr_ios));
        io_info->wareq_sz = (cur->wr_sectors - last->wr_sectors) / ((double)(cur->wr_ios - last->wr_ios)) / 2;
    }

    io_info->rd_speed = S_VALUE(last->rd_ios, cur->rd_ios, period);
    io_info->wr_speed = S_VALUE(last->wr_ios, cur->wr_ios, period);

    io_info->rdkb_speed = S_VALUE(last->rd_sectors, cur->rd_sectors, period) / 2;
    io_info->wrkb_speed = S_VALUE(last->wr_sectors, cur->wr_sectors, period) / 2;

    io_info->util = S_VALUE(last->io_ticks, cur->io_ticks, period) / 10.0;

    io_info->aqu_sz = S_VALUE(last->time_in_queue, cur->time_in_queue, period) / 1000.0;

    return;
}

static void report_disk_iostat(const char *disk_name, disk_io_stats *io_info, struct ipc_body_s *ipc_body)
{
    char entityid[LINE_BUF_LEN];
    struct event_info_s evt = {0};

    if (ipc_body->probe_param.logs == 0) {
        return;
    }

    entityid[0] = 0;

    if (ipc_body->probe_param.res_percent_upper > 0 && io_info->util > ipc_body->probe_param.res_percent_upper) {
        (void)snprintf(entityid, sizeof(entityid), "%s", disk_name);
        evt.entityName = ENTITY_DISK_NAME;
        evt.entityId = entityid;
        evt.metrics = "util";
        evt.dev = disk_name;

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "Disk device saturated(%.2f%%).",
                    io_info->util);
    }
}

/*
 [root@localhost ~]# iostat -xd -t 60
 Device r/s rkB/s r_await rareq-sz w/s wkB/s w_await wareq-sz d/s dkB/s drqm/s %drqm d_await dareq-sz aqu-sz %util
  sda  0.28 19.59  0.58    68.93  1.69 65.02  0.81    38.57  0.00  0.00  0.00  0.00   0.00     0.00    0.00  0.09

 [root@localhost ~]# cat /proc/diskstats
   8       0 sda 28113 601 3643572 9344 119389 109397 12096368 103830 0 98049 69319 0 0 0 0
                  3          5      6     7              9       10       12
 */
static disk_stats *g_disk_stats = NULL;
static int g_disk_dev_num;
static int g_first_flag;

int system_iostat_probe(struct ipc_body_s *ipc_body)
{
    FILE *f = NULL;
    char line[LINE_BUF_LEN];
    disk_stats temp;
    disk_io_stats io_datas;
    int index;

    f = popen(SYSTEM_DISKSTATS_CMD, "r");
    if (f == NULL) {
        return -1;
    }

    index = 0;
    while (!feof(f) && index < g_disk_dev_num) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            (void)pclose(f);
            return -1;
        }
        (void)memcpy(&temp, &g_disk_stats[index], sizeof(disk_stats));
        if (get_diskstats_fields(line, &g_disk_stats[index]) < 0) {
            continue;
        }

        if (g_first_flag == 1) {
            (void)memset(&io_datas, 0, sizeof(disk_io_stats));
        } else {
            cal_disk_io_stats(&temp, &g_disk_stats[index], &io_datas, ipc_body->probe_param.period);
        }

        (void)nprobe_fprintf(stdout,
            "|%s|%s|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f|\n",
            METRICS_IOSTAT_NAME,
            g_disk_stats[index].disk_name,
            io_datas.rd_speed,
            io_datas.rdkb_speed,
            io_datas.rd_await,
            io_datas.rareq_sz,
            io_datas.wr_speed,
            io_datas.wrkb_speed,
            io_datas.wr_await,
            io_datas.wareq_sz,
            io_datas.aqu_sz,
            io_datas.util);
        /* event_output */
        report_disk_iostat(g_disk_stats[index].disk_name, &io_datas, ipc_body);

        index++;
    }
    g_first_flag = 0;
    (void)pclose(f);
    return 0;
}

static int get_diskdev_num(int *num)
{
    FILE *f = NULL;
    char line[LINE_BUF_LEN];

    f = popen(SYSTEM_DISK_DEV_NUM, "r");
    if (f == NULL) {
        return -1;
    }
    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        (void)pclose(f);
        return -1;
    }
    SPLIT_NEWLINE_SYMBOL(line);
    *num = atoi(line);
    (void)pclose(f);
    return 0;
}

int system_iostat_init(void)
{
    int ret = get_diskdev_num(&g_disk_dev_num);
    if (ret < 0 || g_disk_dev_num <= 0) {
        return -1;
    }
    g_disk_stats = malloc(g_disk_dev_num * sizeof(disk_stats));
    if (g_disk_stats == NULL) {
        return -1;
    }
    (void)memset(g_disk_stats, 0, g_disk_dev_num * sizeof(disk_stats));

    g_first_flag = 1;

    return 0;
}

void system_disk_destroy(void)
{
    df_stats *item, *tmp;

    if (g_df_tbl != NULL) {
        HASH_ITER(hh, g_df_tbl, item, tmp) {
            HASH_DEL(g_df_tbl, item);
            free(item);
        }
    }

    return;
}

void system_iostat_destroy(void)
{
    if (g_disk_stats != NULL) {
        (void)free(g_disk_stats);
        g_disk_stats = NULL;
    }
}