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
 * Author: luzhihao
 * Create: 2022-10-22
 * Description: io probe
 ******************************************************************************/
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "args.h"
#include "io_trace_scsi.skel.h"
#include "io_trace_nvme.skel.h"
#include "io_trace_virtblk.skel.h"
#include "page_cache.skel.h"
#include "io_err.skel.h"
#include "io_count.skel.h"
#include "io_trace.h"
#include "event.h"

#define OO_NAME "block"  // Observation Object name
#define IO_TBL_LATENCY    "io_latency"
#define IO_TBL_PAGECACHE  "io_pagecache"
#define IO_TBL_ERR        "io_err"
#define IO_TBL_COUNT      "io_count"

/* Path to pin map */
#define IO_ARGS_PATH            "/sys/fs/bpf/gala-gopher/__io_args"
#define IO_SAMPLE_PATH          "/sys/fs/bpf/gala-gopher/__io_sample"
#define IO_LATENCY_CHANNEL_PATH "/sys/fs/bpf/gala-gopher/__io_latency_channel"
#define IO_TRACE_PATH           "/sys/fs/bpf/gala-gopher/__io_trace"
#define IO_LATENCY_PATH         "/sys/fs/bpf/gala-gopher/__io_latency"

#define RM_IO_PATH              "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__io*"

#define __LOAD_IO_LATENCY(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, io_args_map, IO_ARGS_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, io_sample_map, IO_SAMPLE_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, io_latency_channel_map, IO_LATENCY_CHANNEL_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, io_trace_map, IO_TRACE_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, io_latency_map, IO_LATENCY_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

#define __LOAD_IO_PROBE(probe_name, end, load) \
    OPEN(probe_name, end, load); \
    MAP_SET_PIN_PATH(probe_name, io_args_map, IO_ARGS_PATH, load); \
    LOAD_ATTACH(probe_name, end, load)

static volatile sig_atomic_t g_stop;
static struct probe_params params = {.period = DEFAULT_PERIOD};
static int io_args_fd;

struct scsi_err_desc_s {
    int scsi_ret_code;
    const char *desc;
};

struct scsi_err_desc_s  scsi_err_desc[] = {
    {SCSI_ERR_HOST_BUSY,            "HOST_BUSY"},
    {SCSI_ERR_DEVICE_BUSY,          "DEVICE_BUSY"},
    {SCSI_ERR_EH_BUSY,              "EH_BUSY"},
    {SCSI_ERR_TARGET_BUSY,          "TARGET_BUSY"},
    {SCSI_ERR_NEEDS_RETRY,          "NEEDS_RETRY"},
    {SCSI_ERR_SUCCESS,              "SUCCESS"},
    {SCSI_ERR_FAILED,               "FAILED"},
    {SCSI_ERR_QUEUED,               "QUEUED"},
    {SCSI_ERR_SOFT_ERROR,           "SOFT_ERROR"},
    {SCSI_ERR_ADD_TO_MLQUEUE,       "ADD_TO_MLQUEUE"},
    {SCSI_ERR_TIMEOUT,              "TIMEOUT_ERROR"},
    {SCSI_ERR_RETURN_NOT_HANDLED,   "NOT_HANDELED"},
    {SCSI_ERR_FAST_IO_FAIL,         "FAST_TO_FAIL"}
};

static const char* get_scis_err_desc(int scsi_err)
{
    for (int i = 0; i < sizeof(scsi_err_desc) / sizeof(struct scsi_err_desc_s); i++) {
        if (scsi_err_desc[i].scsi_ret_code == scsi_err)
            return scsi_err_desc[i].desc;
    }

    return "UNKNOW";
}

struct blk_err_desc_s {
    int ret_code;
    int blk_err_code;
    const char *desc;
};

// Refer to linux souce code: include/linux/blk_types.h
#define BLK_STS_OK                      (0)
#define BLK_STS_NOTSUPP                 (1)
#define BLK_STS_TIMEOUT                 (2)
#define BLK_STS_NOSPC                   (3)
#define BLK_STS_TRANSPORT               (4)
#define BLK_STS_TARGET                  (5)
#define BLK_STS_NEXUS                   (6)
#define BLK_STS_MEDIUM                  (7)
#define BLK_STS_PROTECTION              (8)
#define BLK_STS_RESOURCE                (9)
#define BLK_STS_IOERR                   (10)
#define BLK_STS_DM_REQUEUE              (11)
#define BLK_STS_AGAIN                   (12)
#define BLK_STS_DEV_RESOURCE            (13)
#define BLK_STS_ZONE_RESOURCE           (14)
#define BLK_STS_ZONE_OPEN_RESOURCE      (15)
#define BLK_STS_ZONE_ACTIVE_RESOURCE    (16)
struct blk_err_desc_s  blk_err_desc[] = {
    {0,             BLK_STS_OK,                     "OK"},
    {-EOPNOTSUPP,   BLK_STS_NOTSUPP,                "operation not supported"},
    {-ETIMEDOUT,    BLK_STS_TIMEOUT,                "timeout"},
    {-ENOSPC,       BLK_STS_NOSPC,                  "critical space allocation"},
    {-ENOLINK,      BLK_STS_TRANSPORT,              "recoverable transport"},
    {-EREMOTEIO,    BLK_STS_TARGET,                 "critical target"},
    {-EBADE,        BLK_STS_NEXUS,                  "critical nexus"},
    {-ENODATA,      BLK_STS_MEDIUM,                 "critical medium"},
    {-EILSEQ,       BLK_STS_PROTECTION,             "protection"},
    {-ENOMEM,       BLK_STS_RESOURCE,               "kernel resource"},
    {-EBUSY,        BLK_STS_DEV_RESOURCE,           "device resource"},
    {-EAGAIN,       BLK_STS_AGAIN,                  "nonblocking retry"},
    {-EREMCHG,      BLK_STS_DM_REQUEUE,             "dm internal retry"},
    {-ETOOMANYREFS, BLK_STS_ZONE_OPEN_RESOURCE,     "open zones exceeded"},
    {-EOVERFLOW,    BLK_STS_ZONE_ACTIVE_RESOURCE,   "active zones exceeded"},
    {-EIO,          BLK_STS_IOERR,                  "I/O error"}
};

static const char* get_blk_err_desc(int ret_err, int *blk_err)
{
    for (int i = 0; i < sizeof(blk_err_desc) / sizeof(struct blk_err_desc_s); i++) {
        if (blk_err_desc[i].ret_code == ret_err) {
            *blk_err = blk_err_desc[i].blk_err_code;
            return blk_err_desc[i].desc;
        }
    }

    return "UNKNOW";
}

static void sig_int(int signo)
{
    g_stop = 1;
}

/**
lsblk -l | grep 8:0 | awk '{print $1}'
sda
*/
#define LSBLK_LIST_CMD "lsblk -l | grep %d:%d | awk '{print $1}'"
static void get_devname(int major, int minor, char dev_name[], size_t size)
{
    char cmd[COMMAND_LEN];

    cmd[0] = 0;
    (void)sprintf(cmd, LSBLK_LIST_CMD, major, minor);

    (void)exec_cmd((const char *)cmd, dev_name, size);
    return;
}

#define IS_LOWERCASE_LEETER(a) (((a) >= 'a') && ((a) <= 'z'))
static char* __get_first_letter_pos(char *buf)
{
    char *p;
    size_t pos;
    size_t len = strlen(buf);
    if (len == 0) {
        return NULL;
    }

    pos = 0;
    p = buf + pos;
    while ((pos < len) && (!IS_LOWERCASE_LEETER(*p))) {
        pos++;
        p = buf + pos;
    }
    
    if (pos >= len) {
        return NULL;
    }
    return p;
}

#define LSBLK_TREE_CMD "lsblk -t | awk 'NR > 1 {print $1}'"
static void get_diskname(const char* dev_name, char *disk_name, size_t size)
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    char *p;
    char last_disk_name[DISK_NAME_LEN];

    cmd[0] = 0;
    (void)strncpy(cmd, LSBLK_TREE_CMD, COMMAND_LEN);
    f = popen(cmd, "r");
    if (f == NULL) {
        return;
    }
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        p = __get_first_letter_pos(line);
        if (p && (p == line)) {
            // record last disk name
            last_disk_name[0] = 0;
            (void)strncpy(last_disk_name, p, DISK_NAME_LEN);
        }

        if (strcmp(dev_name, last_disk_name) == 0) {
            (void)strncpy(disk_name, dev_name, size);
        }

        if (p && (p != line) && (strcmp(dev_name, p) == 0)) {
            (void)strncpy(disk_name, last_disk_name, size);
            break;
        }
    }

    pclose(f);
    return;
}

static int get_devt(char *dev_name, int *major, int *minor)
{
    char sys_file[PATH_LEN];
    char cmd[COMMAND_LEN];
    char dev[16];
    FILE *fp;

    sys_file[0] = 0;
    (void)snprintf(sys_file, PATH_LEN, "/sys/block/%s/dev", dev_name);
    if (access(sys_file, 0)) {
        sys_file[0] = 0;
        (void)snprintf(sys_file, PATH_LEN, "/sys/block/*/%s/../dev", dev_name);
    }
    if (access(sys_file, 0)) {
        fprintf(stderr, "dev \'%s\' not exist.\n", dev_name);
        return -1;
    }

    cmd[0] = 0;
    (void)sprintf(cmd, "cat %s 2>/dev/null", sys_file);
    if ((fp = popen(cmd, "r")) == NULL) {
        fprintf(stderr, "exec \'%s\' fail\n", cmd);
        return -1;
    }

    dev[0] = 0;
    while (fgets(dev, sizeof(dev) - 1, fp)) {
        if (sscanf(dev, "%d:%d", major, minor) != 2) {
            pclose(fp);
            return -1;
        }
    }
    pclose(fp);
    return 0;
}

#define __ENTITY_ID_LEN 32
static void __build_entity_id(int major, int minor, char *buf, int buf_len)
{
    (void)snprintf(buf, buf_len, "%d_%d", major, minor);
}

static void rcv_io_latency_thr(struct io_latency_s *io_latency)
{
    char entityId[__ENTITY_ID_LEN];
    unsigned int latency_thr_us;
    struct event_info_s evt = {0};
    char dev_name[DISK_NAME_LEN];
    char disk_name[DISK_NAME_LEN];

    if (params.logs == 0) {
        return;
    }

    latency_thr_us = params.latency_thr << 3; // milliseconds to microseconds
    if ((latency_thr_us > 0) && (io_latency->latency[IO_STAGE_BLOCK].max >= latency_thr_us)) {
        entityId[0] = 0;
        __build_entity_id(io_latency->major, io_latency->first_minor, entityId, __ENTITY_ID_LEN);

        dev_name[0] = 0;
        disk_name[0] = 0;
        get_devname(io_latency->major, io_latency->first_minor, dev_name, DISK_NAME_LEN);
        get_diskname((const char*)dev_name, disk_name, DISK_NAME_LEN);

        evt.entityName = OO_NAME;
        evt.entityId = entityId;
        evt.metrics = "latency_req_max";
        evt.dev = disk_name;

        report_logs((const struct event_info_s *)&evt,
                    EVT_SEC_WARN,
                    "IO latency occured."
                    "(Disk %s(%d:%d), COMM %s, PID %u, op: %s, datalen %u, "
                    "drv_latency %llu, dev_latency %llu)",
                    disk_name, io_latency->major, io_latency->first_minor,
                    io_latency->comm, io_latency->proc_id, io_latency->rwbs, io_latency->data_len,
                    io_latency->latency[IO_STAGE_DRIVER].max,
                    io_latency->latency[IO_STAGE_DEVICE].max);
    }
    return;
}

static void rcv_pagecache_stats(void *ctx, int cpu, void *data, __u32 size)
{
    char dev_name[DISK_NAME_LEN];
    char disk_name[DISK_NAME_LEN];
    struct pagecache_stats_s *pagecache_stats = data;

    dev_name[0] = 0;
    disk_name[0] = 0;
    get_devname(pagecache_stats->major, pagecache_stats->first_minor, dev_name, DISK_NAME_LEN);
    get_diskname((const char*)dev_name, disk_name, DISK_NAME_LEN);

    (void)fprintf(stdout, "|%s|%d|%d|%s|%s"
        "|%u|%u|%u|%u|\n",

        IO_TBL_PAGECACHE,
        pagecache_stats->major,
        pagecache_stats->first_minor,
        dev_name,
        disk_name,

        pagecache_stats->access_pagecache,
        pagecache_stats->mark_buffer_dirty,
        pagecache_stats->load_page_cache,
        pagecache_stats->mark_page_dirty);
    (void)fflush(stdout);
}

static void rcv_io_count(void *ctx, int cpu, void *data, __u32 size)
{
    char dev_name[DISK_NAME_LEN];
    char disk_name[DISK_NAME_LEN];
    struct io_count_s *io_count = data;

    dev_name[0] = 0;
    disk_name[0] = 0;
    get_devname(io_count->major, io_count->first_minor, dev_name, DISK_NAME_LEN);
    get_diskname((const char*)dev_name, disk_name, DISK_NAME_LEN);

    (void)fprintf(stdout, "|%s|%d|%d|%s|%s"
        "|%llu|%llu|\n",

        IO_TBL_COUNT,
        io_count->major,
        io_count->first_minor,
        dev_name,
        disk_name,

        io_count->read_bytes,
        io_count->write_bytes);
    (void)fflush(stdout);
}

static void rcv_io_latency(void *ctx, int cpu, void *data, __u32 size)
{
    char dev_name[DISK_NAME_LEN];
    char disk_name[DISK_NAME_LEN];
    struct io_latency_s *io_latency = data;

    rcv_io_latency_thr(io_latency);

    dev_name[0] = 0;
    disk_name[0] = 0;
    get_devname(io_latency->major, io_latency->first_minor, dev_name, DISK_NAME_LEN);
    get_diskname((const char*)dev_name, disk_name, DISK_NAME_LEN);

    (void)fprintf(stdout, "|%s|%d|%d|%s|%s"
        "|%llu|%llu|%llu|%llu|%u"
        "|%llu|%llu|%llu|%llu|%u"
        "|%llu|%llu|%llu|%llu|%u|\n",

        IO_TBL_LATENCY,
        io_latency->major,
        io_latency->first_minor,
        dev_name,
        disk_name,

        io_latency->latency[IO_STAGE_BLOCK].max,
        io_latency->latency[IO_STAGE_BLOCK].last,
        io_latency->latency[IO_STAGE_BLOCK].sum,
        io_latency->latency[IO_STAGE_BLOCK].jitter,
        io_latency->latency[IO_STAGE_BLOCK].count,

        io_latency->latency[IO_STAGE_DRIVER].max,
        io_latency->latency[IO_STAGE_DRIVER].last,
        io_latency->latency[IO_STAGE_DRIVER].sum,
        io_latency->latency[IO_STAGE_DRIVER].jitter,
        io_latency->latency[IO_STAGE_DRIVER].count,

        io_latency->latency[IO_STAGE_DEVICE].max,
        io_latency->latency[IO_STAGE_DEVICE].last,
        io_latency->latency[IO_STAGE_DEVICE].sum,
        io_latency->latency[IO_STAGE_DEVICE].jitter,
        io_latency->latency[IO_STAGE_DEVICE].count);
    (void)fflush(stdout);
}

static void rcv_io_err(void *ctx, int cpu, void *data, __u32 size)
{
    int blk_err = 0;
    char entityId[__ENTITY_ID_LEN];
    struct io_err_s *io_err = data;
    struct event_info_s evt = {0};
    char dev_name[DISK_NAME_LEN];
    char disk_name[DISK_NAME_LEN];

    if (params.logs == 0) {
        return;
    }

    entityId[0] = 0;
    __build_entity_id(io_err->major, io_err->first_minor, entityId, __ENTITY_ID_LEN);

    dev_name[0] = 0;
    disk_name[0] = 0;
    get_devname(io_err->major, io_err->first_minor, dev_name, DISK_NAME_LEN);
    get_diskname((const char*)dev_name, disk_name, DISK_NAME_LEN);

    evt.entityName = OO_NAME;
    evt.entityId = entityId;
    evt.metrics = "err_code";
    evt.dev = disk_name;

    const char *blk_err_desc = get_blk_err_desc(io_err->err_code, &blk_err);
    report_logs((const struct event_info_s *)&evt,
                EVT_SEC_WARN,
                "IO errors occured."
                "(Disk %s(%d:%d), COMM %s, PID %u, op: %s, datalen %u, "
                "blk_err(%d) '%s', scsi_err(%d) '%s', timestamp %f)",
                disk_name, io_err->major, io_err->first_minor,
                io_err->comm, io_err->proc_id, io_err->rwbs, io_err->data_len,
                blk_err, blk_err_desc, io_err->scsi_err, get_scis_err_desc(io_err->scsi_err),
                io_err->timestamp / 1000000.0);

    (void)fflush(stdout);
}

#define VIRTBLK_PROBE   "virtio"
#define NVME_PROBE      "nvme"
#define SCSI_PROBE      "target"

#define LS_BLOCK_CMD "/usr/bin/ls -l /sys/class/block | grep %s | wc -l"
static char is_load_probe(char *probe_name)
{
    char cmd[COMMAND_LEN];
    char count_str[INT_LEN];
    int count;

    cmd[0] = 0;
    (void)sprintf(cmd, LS_BLOCK_CMD, probe_name);
    count_str[0] = 0;
    if (exec_cmd(cmd, count_str, INT_LEN) < 0) {
        return 0;
    }

    count = atoi((const char *)count_str);

    return (count > 0) ? 1 : 0;
}

static void load_io_args(int fd, struct probe_params* args)
{
    u32 key = 0;
    int major;
    int minor;
    struct io_trace_args_s io_args = {0};

    if ((args->target_dev[0] != 0) && (!get_devt(args->target_dev, &major, &minor))) {
        io_args.target_major = major;
        io_args.target_first_minor = minor;
    }
    io_args.report_period = NS(args->period);
    io_args.sample_interval = (u64)((u64)args->sample_period * 1000 * 1000);

    (void)bpf_map_update_elem(fd, &key, &io_args, BPF_ANY);
}

int main(int argc, char **argv)
{
    int ret = 0;
    char scsi_probe, nvme_probe, virtblk_probe;
    char is_load_err, is_load_count, is_load_pagecache;
    FILE *fp = NULL;
    struct perf_buffer *io_err_pb = NULL, *io_latency_pb = NULL;
    struct perf_buffer *page_cache_pb = NULL, *io_count_pb = NULL;

    ret = args_parse(argc, argv, &params);
    if (ret != 0) {
        return -1;
    }

    fp = popen(RM_IO_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    scsi_probe = is_load_probe(SCSI_PROBE) & IS_LOAD_PROBE(params.load_probe, IO_PROBE_TRACE);
    nvme_probe = is_load_probe(NVME_PROBE) & IS_LOAD_PROBE(params.load_probe, IO_PROBE_TRACE);
    virtblk_probe = is_load_probe(VIRTBLK_PROBE) & IS_LOAD_PROBE(params.load_probe, IO_PROBE_TRACE);

    is_load_err = IS_LOAD_PROBE(params.load_probe, IO_PROBE_ERR);
    is_load_count = IS_LOAD_PROBE(params.load_probe, IO_PROBE_COUNT);
    is_load_pagecache = IS_LOAD_PROBE(params.load_probe, IO_PROBE_PAGECACHE);

    INIT_BPF_APP(ioprobe, EBPF_RLIM_LIMITED);

    __LOAD_IO_PROBE(io_count, err6, is_load_count);
    __LOAD_IO_PROBE(io_err, err5, is_load_err);
    __LOAD_IO_PROBE(page_cache, err4, is_load_pagecache);
    __LOAD_IO_LATENCY(io_trace_scsi, err3, scsi_probe);
    __LOAD_IO_LATENCY(io_trace_nvme, err2, nvme_probe);
    __LOAD_IO_LATENCY(io_trace_virtblk, err, virtblk_probe);

    if (is_load_pagecache) {
        page_cache_pb = create_pref_buffer(GET_MAP_FD(page_cache, page_cache_channel_map),
                                           rcv_pagecache_stats);
        io_args_fd = GET_MAP_FD(page_cache, io_args_map);
    }

    if (is_load_count) {
        io_count_pb = create_pref_buffer(GET_MAP_FD(io_count, io_count_channel_map),
                                           rcv_io_count);
        io_args_fd = GET_MAP_FD(io_count, io_args_map);
    }

    if (is_load_err) {
        io_err_pb = create_pref_buffer(GET_MAP_FD(io_err, io_err_channel_map),
                                           rcv_io_err);
        io_args_fd = GET_MAP_FD(io_err, io_args_map);
    }

    if (scsi_probe) {
        io_latency_pb = create_pref_buffer(GET_MAP_FD(io_trace_scsi, io_latency_channel_map),
                                           rcv_io_latency);
        io_args_fd = GET_MAP_FD(io_trace_scsi, io_args_map);
    } else if (nvme_probe) {
        io_latency_pb = create_pref_buffer(GET_MAP_FD(io_trace_nvme, io_latency_channel_map),
                                           rcv_io_latency);
        io_args_fd = GET_MAP_FD(io_trace_nvme, io_args_map);
    } else if (virtblk_probe) {
        io_latency_pb = create_pref_buffer(GET_MAP_FD(io_trace_virtblk, io_latency_channel_map),
                                           rcv_io_latency);
        io_args_fd = GET_MAP_FD(io_trace_virtblk, io_args_map);
    }

    load_io_args(io_args_fd, &params);

    if (scsi_probe || nvme_probe || virtblk_probe) {
        if (io_latency_pb == NULL) {
            fprintf(stderr, "Load io latency prog failed.\n");
            goto err;
        }
    }

    if (is_load_pagecache) {
        if (page_cache_pb == NULL) {
            fprintf(stderr, "Load io page-cache prog failed.\n");
            goto err;
        }
    }

    if (is_load_count) {
        if (io_count_pb == NULL) {
            fprintf(stderr, "Load io count prog failed.\n");
            goto err;
        }
    }

    if (is_load_err) {
        if (io_err_pb == NULL) {
            fprintf(stderr, "Load io err prog failed.\n");
            goto err;
        }
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto err;
    }

    printf("Successfully started!\n");

    while (!g_stop) {
        if (io_latency_pb) {
            ret = perf_buffer__poll(io_latency_pb, THOUSAND);
            if (ret < 0) {
                break;
            }
        }

        if (io_err_pb) {
            ret = perf_buffer__poll(io_err_pb, THOUSAND);
            if (ret < 0) {
                break;
            }
        }

        if (io_count_pb) {
            ret = perf_buffer__poll(io_count_pb, THOUSAND);
            if (ret < 0) {
                break;
            }
        }

        if (page_cache_pb) {
            ret = perf_buffer__poll(page_cache_pb, THOUSAND);
            if (ret < 0) {
                break;
            }
        }
    }

err:
    if (io_latency_pb) {
        perf_buffer__free(io_latency_pb);
    }
    if (io_err_pb) {
        perf_buffer__free(io_err_pb);
    }
    if (io_count_pb) {
        perf_buffer__free(io_count_pb);
    }
    if (page_cache_pb) {
        perf_buffer__free(page_cache_pb);
    }
    if (virtblk_probe) {
        UNLOAD(io_trace_virtblk);
    }
err2:
    if (nvme_probe) {
        UNLOAD(io_trace_nvme);
    }
err3:
    if (scsi_probe) {
        UNLOAD(io_trace_scsi);
    }
err4:
    if (is_load_pagecache) {
        UNLOAD(page_cache);
    }
err5:
    if (is_load_err) {
        UNLOAD(io_err);
    }
err6:
    if (is_load_count) {
        UNLOAD(io_count);
    }
    return ret;
}

