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
 * Description: system netdev probe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include "event.h"
#include "nprobe_fprintf.h"
#include "system_net.h"

#define METRICS_TCP_NAME        "system_tcp"
#define METRICS_UDP_NAME        "system_udp"
#define METRICS_NIC_NAME        "nic"
#define ENTITY_NIC_NAME         "nic"
#define SYSTEM_NET_SNMP_PATH    "/proc/net/snmp"
#define SYSTEM_NET_DEV_PATH     "/proc/net/dev"
#define SYSTEM_NET_DEV_STATUS   "ethtool %s | grep \"Link detected\" | awk '{print $NF}'"
#define SYSTEM_NET_QDISC_SHOW   "tc -s -d qdisc show dev"

#define NETSNMP_TCP_FIELD_NUM   5
#define NETSNMP_UDP_FIELD_NUM   2
static int get_netsnmp_fileds(const char *net_snmp_info, net_snmp_stat *stats)
{
    int ret;
    char *colon = strchr(net_snmp_info, ':');
    if (colon == NULL) {
        DEBUG("[SYSTEM_NET] net_snmp not find symbol ':' \n");
        return -1;
    }
    *colon = '\0';

    if (strcmp(net_snmp_info, "Tcp") == 0) {
        ret = sscanf(colon + 1,
            "%*Lu %*Lu %*Lu %*Lu %*Lu %*Lu %*Lu %*Lu %llu %llu %llu %llu %llu",
            &stats->tcp_curr_estab, &stats->tcp_in_segs, &stats->tcp_out_segs,
            &stats->tcp_retrans_segs, &stats->tcp_in_errs);
        if (ret < NETSNMP_TCP_FIELD_NUM) {
            return -1;
        }
        return 0;
    }
    if (strcmp(net_snmp_info, "Udp") == 0) {
        ret = sscanf(colon + 1, "%llu %*Lu %*Lu %llu",
            &stats->udp_in_datagrams, &stats->udp_out_datagrams);
        if (ret < NETSNMP_UDP_FIELD_NUM) {
            return -1;
        }
        return 0;
    }

    return -1;
}

/*
 [root@master ~]# cat /proc/net/snmp | grep Tcp: | awk '{print $10 ":" $11 ":" $12 ":" $13 ":"  $14}' | tail -n1
 4:2413742:2164290:300:0
 [root@master ~]# cat /proc/net/snmp | grep Udp: | awk '{print $2 ":" $5}' | tail -n1
 1968:1968
 */
static net_snmp_stat g_snmp_stats;

int system_tcp_probe(void)
{
    FILE* f = NULL;
    char line[LINE_BUF_LEN];
    net_snmp_stat temp = {0};
    int ret;

    f = fopen(SYSTEM_NET_SNMP_PATH, "r");
    if (f == NULL) {
        return -1;
    }
    /* fopen success, copy g_snmp_stats to temp */
    (void)memcpy(&temp, &g_snmp_stats, sizeof(net_snmp_stat));

    /* parse lines */
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        if (get_netsnmp_fileds(line, (net_snmp_stat *)&g_snmp_stats) < 0) {
            continue;
        }
    }
    /* output */
    (void)nprobe_fprintf(stdout, "|%s|%s|%llu|%llu|%llu|%llu|%llu|\n",
        METRICS_TCP_NAME,
        "/proc/dev/snmp",
        g_snmp_stats.tcp_curr_estab,
        g_snmp_stats.tcp_in_segs - temp.tcp_in_segs,
        g_snmp_stats.tcp_out_segs - temp.tcp_out_segs,
        g_snmp_stats.tcp_retrans_segs - temp.tcp_retrans_segs,
        g_snmp_stats.tcp_in_errs - temp.tcp_in_errs);

    (void)nprobe_fprintf(stdout, "|%s|%s|%llu|%llu|\n",
        METRICS_UDP_NAME,
        "/proc/dev/snmp",
        g_snmp_stats.udp_in_datagrams - temp.udp_in_datagrams,
        g_snmp_stats.udp_out_datagrams - temp.udp_out_datagrams);

    (void)fclose(f);
    return 0;
}

void system_tcp_init(void)
{
    (void)memset(&g_snmp_stats, 0, sizeof(net_snmp_stat));
}

static int get_netdev_name(const char *line, char dev_name[])
{
    int i;
    int index = 0;

    if (line == NULL) {
        return -1;
    }
    for (i = 0; (line[i] != ':') && (line[i] != '\0'); i++) {
        if (line[i] != ' ') {
            dev_name[index++] = line[i];
        }
    }
    dev_name[index] = '\0';
    return 0;
}

#define NETDEV_FIELD_NUM        8
static int get_netdev_fileds(const char *net_dev_info, net_dev_stat *stats)
{
    int i, ret;
    char *devinfo = (char *)net_dev_info;

    /* parse fileds */
    ret = sscanf(devinfo,
        "%*s %llu %llu %llu %llu %*Lu %*Lu %*Lu %*Lu %llu %llu %llu %llu %*Lu %*Lu %*Lu %*Lu",
        &stats->rx_bytes, &stats->rx_packets, &stats->rx_errs, &stats->rx_dropped,
        &stats->tx_bytes, &stats->tx_packets, &stats->tx_errs, &stats->tx_dropped);
    if (ret < NETDEV_FIELD_NUM) {
        DEBUG("[SYSTEM_NET] system_net.probe faild get net_dev metrics.\n");
        return -1;
    }
    return 0;
}

static int get_netdev_status(net_dev_stat *stats)
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    // default is DOWN
    stats->net_status = 0;

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, SYSTEM_NET_DEV_STATUS, stats->dev_name);
    f = popen(cmd, "r");
    if (f == NULL) {
        ERROR("[SYSTEM_NET] ethtool dev(%s) failed, popen error.\n", stats->dev_name);
        return -1;
    }
    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        ERROR("[SYSTEM_NET] ethtool dev(%s) failed, line is NULL.\n", stats->dev_name);
        (void)pclose(f);
        return -1;
    }
    SPLIT_NEWLINE_SYMBOL(line);
    if (!strcasecmp(line, "yes")) {
        stats->net_status = 1;
    }

    (void)pclose(f);
    return 0;
}

static int do_read_qdisc_line(char *dev_name, char *keywords, char *filter, char line[])
{
    FILE *f = NULL;
    char cmd[COMMAND_LEN];
    char *fmt = "%s %s | grep \"%s\" | awk \'%s\'";  // eg: tc qdis show dev eth0 | grep "backlog" | awk '{print $NF}'

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, fmt, SYSTEM_NET_QDISC_SHOW, dev_name, keywords, filter);
    f = popen(cmd, "r");
    if (f == NULL) {
        ERROR("[SYSTEM_NET] get net(%s) qdisc(%s) failed, popen error.\n", dev_name, keywords);
        return -1;
    }
    line[0] = 0;
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        ERROR("[SYSTEM_NET] get net(%s) qdisc(%s) failed, line is NULL.\n", dev_name, keywords);
        (void)pclose(f);
        return -1;
    }
    SPLIT_NEWLINE_SYMBOL(line);

    (void)pclose(f);
    return 0;
}

#define QDISC_SENT_FILED_NUM        2
#define QDISC_BACKLOG_FIELD_NUM     1
static int get_netdev_qdisc(net_dev_stat *stats)
{
    int ret;
    char line[LINE_BUF_LEN];

    ret = do_read_qdisc_line(stats->dev_name, "Sent", "NR==1{print $7$9}", line);
    if (ret < 0 || line == NULL) {
        return -1;
    }
    ret = sscanf(line, "%d%*c%d",&stats->tc_sent_drop_count, &stats->tc_sent_overlimits_count);
    if (ret < QDISC_SENT_FILED_NUM) {
        ERROR("[SYSTEM_NET] faild get qdisc sent metrics.\n");
        return -1;
    }

    ret = do_read_qdisc_line(stats->dev_name, "backlog", "NR==1{print $3}", line);
    if (ret < 0 || line == NULL) {
        return -1;
    }
    ret = sscanf(line, "%d%*c",&stats->tc_backlog_count);
    if (ret < QDISC_BACKLOG_FIELD_NUM) {
        ERROR("[SYSTEM_NET] faild get qdisc backlog metrics.\n");
        return -1;
    }

    ret = do_read_qdisc_line(stats->dev_name, "ecn_mark", "{print $NF}", line);
    if (ret < 0 || line == NULL) {
        return -1;
    }
    stats->tc_ecn_mark = (u64)atoi(line);

    return 0;
}

static char g_phy_netdev_list[MAX_NETDEV_NUM][NET_DEVICE_NAME_SIZE];

static int is_physical_netdev(char *dev_name, int dev_num)
{
    for (int i = 0; i < dev_num; i++) {
        if (!strcmp(dev_name, g_phy_netdev_list[i])) {
            return 1;
        }
    }
    return 0;
}

static void report_netdev(net_dev_stat *new_info, net_dev_stat *old_info, struct probe_params *params)
{
    char entityid[LINE_BUF_LEN];
    u64 tx_drops;
    u64 rx_drops;
    u64 tx_errs;
    u64 rx_errs;

    if (params->logs == 0) {
        return;
    }

    entityid[0] = 0;
    tx_drops = new_info->tx_dropped - old_info->tx_dropped;
    rx_drops = new_info->rx_dropped - old_info->rx_dropped;
    tx_errs = new_info->tx_errs - old_info->tx_errs;
    rx_errs = new_info->rx_errs - old_info->rx_errs;

    if (tx_drops > params->drops_count_thr) {
        (void)strncpy(entityid, new_info->dev_name, LINE_BUF_LEN - 1);
        report_logs(ENTITY_NIC_NAME,
                    entityid,
                    "tx_dropped",
                    EVT_SEC_WARN,
                    "net device tx queue drops(%llu).",
                    tx_drops);
    }
    if (rx_drops > params->drops_count_thr) {
        if (entityid[0] == 0) {
            (void)strncpy(entityid, new_info->dev_name, LINE_BUF_LEN - 1);
        }
        report_logs(ENTITY_NIC_NAME,
                    entityid,
                    "rx_dropped",
                    EVT_SEC_WARN,
                    "net device rx queue drops(%llu).",
                    rx_drops);
    }
    if (tx_errs > params->drops_count_thr) {
        if (entityid[0] == 0) {
            (void)strncpy(entityid, new_info->dev_name, LINE_BUF_LEN - 1);
        }
        report_logs(ENTITY_NIC_NAME,
                    entityid,
                    "tx_errs",
                    EVT_SEC_WARN,
                    "net device tx queue errors(%llu).",
                    tx_errs);
    }
    if (rx_errs > params->drops_count_thr) {
        if (entityid[0] == 0) {
            (void)strncpy(entityid, new_info->dev_name, LINE_BUF_LEN - 1);
        }
        report_logs(ENTITY_NIC_NAME,
                    entityid,
                    "rx_errs",
                    EVT_SEC_WARN,
                    "net device rx queue errors(%llu).",
                    rx_errs);
    }
}

/*
 [root@ecs-ee4b-0019 ~]# cat /proc/net/dev
 Inter-|   Receive                                                |  Transmit
  face |   bytes    packets errs drop fifo frame cmpsed multi|bytes    packets errs drop fifo colls carrier compressed
  eth0: 58324993484 49590277  0    0    0    0     0     0   26857829724 19952463  0    0    0    0      0      0
    lo:  878352945  6861344   0    0    0    0     0     0    878352945  6861344   0    0    0    0      0      0
 */
static net_dev_stat *g_dev_stats = NULL;
static int g_netdev_num;

int system_net_probe(struct probe_params *params)
{
    FILE* f = NULL;
    char line[LINE_BUF_LEN];
    char dev_name[NET_DEVICE_NAME_SIZE];
    net_dev_stat temp;
    int index = 0;

    f = fopen(SYSTEM_NET_DEV_PATH, "r");
    if (f == NULL) {
        return -1;
    }
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            fclose(f);
            return 0;
        }
        if (strchr(line, '|') != NULL) {
            continue;
        }
        if (index > g_netdev_num) {
            ERROR("[SYSTEM_NET] net_probe records beyond max netdev nums(%d).\n", g_netdev_num);
            continue;
        }
        (void)get_netdev_name(line, dev_name);
        if (is_physical_netdev(dev_name, g_netdev_num) != 1) {
            continue;
        }
        (void)strncpy(g_dev_stats[index].dev_name, dev_name, NET_DEVICE_NAME_SIZE - 1);

        (void)memcpy(&temp, &g_dev_stats[index], sizeof(net_dev_stat));
        if (get_netdev_fileds(line, &g_dev_stats[index]) < 0) {
            continue;
        }
        get_netdev_status(&g_dev_stats[index]);
        get_netdev_qdisc(&g_dev_stats[index]);

        (void)nprobe_fprintf(stdout,
            "|%s|%s|%s|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%llu|%.2f|%.2f|%llu|%llu|%llu|%llu|\n",
            METRICS_NIC_NAME,
            g_dev_stats[index].dev_name,
            g_dev_stats[index].net_status == 1 ? "UP" : "DOWN",
            g_dev_stats[index].rx_bytes - temp.rx_bytes,
            g_dev_stats[index].rx_packets - temp.rx_packets,
            g_dev_stats[index].rx_errs - temp.rx_errs,
            g_dev_stats[index].rx_dropped - temp.rx_dropped,
            g_dev_stats[index].tx_bytes - temp.tx_bytes,
            g_dev_stats[index].tx_packets - temp.tx_packets,
            g_dev_stats[index].tx_errs - temp.tx_errs,
            g_dev_stats[index].tx_dropped - temp.tx_dropped,
            SPEED_VALUE(temp.rx_bytes, g_dev_stats[index].rx_bytes, params->period),
            SPEED_VALUE(temp.tx_bytes, g_dev_stats[index].tx_bytes, params->period),
            g_dev_stats[index].tc_sent_drop_count - temp.tc_sent_drop_count,
            g_dev_stats[index].tc_sent_overlimits_count - temp.tc_sent_overlimits_count,
            g_dev_stats[index].tc_backlog_count,
            g_dev_stats[index].tc_ecn_mark);
        /* output event */
        report_netdev(&g_dev_stats[index], &temp, params);
        index++;
    }

    (void)fclose(f);
    return 0;
}

static int load_physical_device(void)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char fpath[COMMAND_LEN];
    g_netdev_num = 0;

    dir = opendir("/sys/class/net");
    if (dir == NULL) {
        return -1;
    }
    while (entry = readdir(dir)) {
        fpath[0] = 0;
        (void)snprintf(fpath, COMMAND_LEN, "/sys/devices/virtual/net/%s", entry->d_name);
        if (access((const char *)fpath, 0) < 0) {
            // this is not virtual device
            strncpy(g_phy_netdev_list[g_netdev_num++], entry->d_name, NET_DEVICE_NAME_SIZE - 1);
        }
    }
    closedir(dir);
    return 0;
}

int system_net_init(void)
{
    if (load_physical_device() < 0 || g_netdev_num <= 0) {
        return -1;
    }
    g_dev_stats = (net_dev_stat *)malloc(g_netdev_num * sizeof(net_dev_stat));
    if (g_dev_stats == NULL) {
        return -1;
    }
    (void)memset(g_dev_stats, 0, g_netdev_num * sizeof(net_dev_stat));
    return 0;
}

void system_net_destroy(void)
{
    if (g_dev_stats != NULL) {
        (void)free(g_dev_stats);
        g_dev_stats = NULL;
    }
}
