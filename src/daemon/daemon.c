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
 * Create: 2021-09-28
 * Description: provide gala-gopher daemon functions
 ******************************************************************************/
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <time.h>
#include <signal.h>

#include "cmd_server.h"
#include "daemon.h"

#define RM_MAP_CMD "/usr/bin/find %s/* 2> /dev/null | /usr/bin/xargs rm -f"
static const ResourceMgr *resouce_msg;

#if GALA_GOPHER_INFO("inner func declaration")
static void *DaemonRunIngress(void *arg);
static void *DaemonRunEgress(void *arg);
static void *DaemonRunSingleProbe(void *arg);
static void *DaemonRunSingleExtendProbe(void *arg);
#endif

#if GALA_GOPHER_INFO("inner func defination")
static void *DaemonRunIngress(void *arg)
{
    IngressMgr *mgr = (IngressMgr *)arg;
    prctl(PR_SET_NAME, "[INGRESS]");
    IngressMain(mgr);
}

static void *DaemonRunEgress(void *arg)
{
    EgressMgr *mgr = (EgressMgr *)arg;
    prctl(PR_SET_NAME, "[EGRESS]");
    EgressMain(mgr);
}

static void *DaemonRunWebServer(void *arg)
{
    http_server_mgr_s *web_server = (http_server_mgr_s *)arg;
    prctl(PR_SET_NAME, "[WEBSERVER]");
    run_http_server_daemon(web_server);
}

static void *DaemonRunRestServer(void *arg)
{
    http_server_mgr_s *rest_server = (http_server_mgr_s *)arg;
    prctl(PR_SET_NAME, "[RESTSERVER]");
    run_http_server_daemon(rest_server);
}

static void *DaemonRunProbeMng(void *arg)
{
    struct probe_mng_s *probe_mng = (struct probe_mng_s *)arg;
    prctl(PR_SET_NAME, "[PROBEMNG]");
    run_probe_mng_daemon(probe_mng);
}


static void *DaemonRunMetadataReport(void *arg)
{
    MeasurementMgr *mgr = (MeasurementMgr *)arg;
    prctl(PR_SET_NAME, "[METAREPORT]");
    (void)ReportMetaDataMain(mgr);
}

static void *DaemonRunMetricsWriteLogs(void *arg)
{
    IMDB_DataBaseMgr *mgr = (IMDB_DataBaseMgr *)arg;
    prctl(PR_SET_NAME, "[METRICLOG]");
    WriteMetricsLogsMain(mgr);
}

#endif

static void CleanData(const ResourceMgr *mgr)
{
#define __SYS_FS_BPF "/sys/fs/bpf/gala-gopher"
    FILE *fp = NULL;
    char cmd[MAX_COMMAND_LEN];

    cmd[0] = 0;
    (void)snprintf(cmd, MAX_COMMAND_LEN, RM_MAP_CMD, __SYS_FS_BPF);
    fp = popen(cmd, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
    DEBUG("[DAEMON] clean data success[%s].\n", cmd);
}

int DaemonRun(ResourceMgr *mgr)
{
    int ret;

    // 0. clean data
    CleanData(mgr);
    resouce_msg = mgr;

    // 1. start ingress thread
    ret = pthread_create(&mgr->ingressMgr->tid, NULL, DaemonRunIngress, mgr->ingressMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create ingress thread failed.(errno:%d, %s)\n", errno, strerror(errno));
        return -1;
    }
    INFO("[DAEMON] create ingress thread success.\n");

    // 2. start egress thread
    ret = pthread_create(&mgr->egressMgr->tid, NULL, DaemonRunEgress, mgr->egressMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create egress thread failed.(errno:%d, %s)\n", errno, strerror(errno));
        return -1;
    }
    INFO("[DAEMON] create egress thread success.\n");

    // 3. start web_server thread
    if (mgr->web_server_mgr == NULL) {
        INFO("[DAEMON] skip create web_server thread.\n");
    } else {
        ret = pthread_create(&mgr->web_server_mgr->tid, NULL, DaemonRunWebServer, mgr->web_server_mgr);
        if (ret != 0) {
            ERROR("[DAEMON] create web_server thread failed.(errno:%d, %s)\n", errno, strerror(errno));
            return -1;
        }
        INFO("[DAEMON] create web_server thread success.\n");
    }

    // 4. start metadata_report thread
    ret = pthread_create(&mgr->mmMgr->tid, NULL, DaemonRunMetadataReport, mgr->mmMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create metadata_report thread failed.(errno:%d, %s)\n", errno, strerror(errno));
        return -1;
    }
    INFO("[DAEMON] create metadata_report thread success.\n");

    // 5. start probe manager thread
    ret = pthread_create(&mgr->probe_mng->tid, NULL, DaemonRunProbeMng, mgr->probe_mng);
    if (ret != 0) {
        ERROR("[DAEMON] create probe_mng thread failed.(errno:%d, %s)\n", errno, strerror(errno));
        return -1;
    }
    INFO("[DAEMON] create probe_mng thread success.\n");

    // 6. start write metricsLogs thread
    ret = pthread_create(&mgr->imdbMgr->metrics_tid, NULL, DaemonRunMetricsWriteLogs, mgr->imdbMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create metrics_write_logs thread failed.(errno:%d, %s)\n", errno, strerror(errno));
        return -1;
    }
    INFO("[DAEMON] create metrics_write_logs thread success.\n");

    // 8. start rest_api_server thread
    if (mgr->rest_server_mgr == NULL) {
        INFO("[DAEMON] skip create rest api server thread.\n");
    } else {
        ret = pthread_create(&mgr->rest_server_mgr->tid, NULL, DaemonRunRestServer, mgr->rest_server_mgr);
        if (ret != 0) {
            ERROR("[DAEMON] create rest api server thread failed.(errno:%d, %s)\n", errno, strerror(errno));
            return -1;
        }
        INFO("[DAEMON] create rest api server thread success.\n");
    }

    // 9. start CmdServer thread
    ret = pthread_create(&mgr->ctl_tid, NULL, CmdServer, NULL);
    if (ret != 0) {
        printf("[DAEMON] create cmd_server thread failed. errno: %d\n", errno);
        return -1;
    }
    printf("[DAEMON] create cmd_server thread success.\n");

    return 0;
}

void DaemonWaitDone(const ResourceMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }

    if (mgr->ingressMgr != NULL && mgr->ingressMgr->tid != 0) {
        pthread_join(mgr->ingressMgr->tid, NULL);
    }

    if (mgr->egressMgr != NULL && mgr->egressMgr->tid != 0) {
        pthread_join(mgr->egressMgr->tid, NULL);
    }

    if (mgr->web_server_mgr != NULL && mgr->web_server_mgr->tid != 0) {
        pthread_join(mgr->web_server_mgr->tid, NULL);
    }

    if (mgr->mmMgr != NULL && mgr->mmMgr->tid != 0) {
        pthread_join(mgr->mmMgr->tid, NULL);
    }

    if (mgr->probe_mng != NULL && mgr->probe_mng->tid != 0) {
        pthread_join(mgr->probe_mng->tid, NULL);
    }

    if (mgr->imdbMgr != NULL && mgr->imdbMgr->metrics_tid != 0) {
        pthread_join(mgr->imdbMgr->metrics_tid, NULL);
    }

    if (mgr->rest_server_mgr != NULL && mgr->rest_server_mgr->tid != 0) {
        pthread_join(mgr->rest_server_mgr->tid, NULL);
    }

    if (mgr->ctl_tid != 0) {
        pthread_join(mgr->ctl_tid, NULL);
        (void)unlink(GALA_GOPHER_CMD_SOCK_PATH);
    }
}

