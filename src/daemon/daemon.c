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

#include "object.h"
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

#if 0
static void *DaemonRunSingleProbe(void *arg)
{
    g_probe = (Probe *)arg;

    char thread_name[MAX_THREAD_NAME_LEN];
    snprintf(thread_name, MAX_THREAD_NAME_LEN - 1, "[PROBE]%s", g_probe->name);
    prctl(PR_SET_NAME, thread_name);

    g_probe->func(&(g_probe->params));
}

static void *DaemonRunSingleExtendProbe(void *arg)
{
    int ret = 0;
    ExtendProbe *probe = (ExtendProbe *)arg;

    char thread_name[MAX_THREAD_NAME_LEN];
    snprintf(thread_name, MAX_THREAD_NAME_LEN - 1, "[EPROBE]%s", probe->name);
    prctl(PR_SET_NAME, thread_name);

    (void)RunExtendProbe(probe);
}
#endif

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

#if 0
static void DaemonKeeplive(int sig)
{
    int ret;
    ExtendProbe *probe;
    const ResourceMgr *mgr = resouce_msg;

    for (int i = 0; i < mgr->extendProbeMgr->probesNum; i++) {
        probe = mgr->extendProbeMgr->probes[i];
        if (probe->is_running == 0) {
            continue;
        }

        if (probe->is_exist == 0) {
#if 0
            ret = IngressRemovePorbe(mgr->ingressMgr, probe);
            if (ret != 0) {
                ERROR("[DAEMON] keeplive probe(%s) failed.\n", probe->name);
                continue;
            }
            ret = IngressAddPorbe(mgr->ingressMgr, probe);
            if (ret != 0) {
                ERROR("[DAEMON] keeplive probe(%s) failed.\n", probe->name);
                continue;
            }
#endif
            (void)pthread_create(&probe->tid, NULL, DaemonRunSingleExtendProbe, probe);
            (void)pthread_detach(probe->tid);

            INFO("[DAEMON] keeplive create probe(%s) thread.\n", probe->name);
            continue;
        }
    }
    return;
}

#define KEEPLIVE_DELAY_START    60  // 1min
#define KEEPLIVE_PERIOD         120 // 2min
static int DaemonCreateTimer(ResourceMgr *mgr)
{
    int ret;
    struct sigevent se;
    struct itimerspec its;
    struct sigaction sa;

    // Set signal handler.
    sa.sa_handler = DaemonKeeplive;
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_flags |= SA_INTERRUPT;

    ret = sigaction(SIGUSR1, &sa, NULL);
    if (ret != 0) {
        ERROR("[DAEMON] set sig action failed(%d)\n", ret);
        goto err;
    }

    // Set Timer signal notification mode
    (void)memset(&se, 0, sizeof(se));
    se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = SIGUSR1;
    se.sigev_value.sival_ptr = CLOCK_REALTIME;

    ret = timer_create(CLOCK_REALTIME, &se, &(mgr->keeplive_timer));
    if (ret != 0) {
        ERROR("[DAEMON] create timer failed(%d)\n", ret);
        goto err;
    }

    (void)memset(&its, 0, sizeof(its));

    its.it_value.tv_sec = KEEPLIVE_DELAY_START;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = KEEPLIVE_PERIOD;
    its.it_interval.tv_nsec = 0;

    ret = timer_settime(mgr->keeplive_timer, 0, &its, NULL);
    if (ret != 0) {
        ERROR("[DAEMON] set timer failed(%d)\n", ret);
        goto err;
    }

    return 0;
err:
    if (mgr->keeplive_timer != 0) {
        (void)timer_delete(mgr->keeplive_timer);
        mgr->keeplive_timer = 0;
    }
    return ret;
}
#endif
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
    ret = pthread_create(&mgr->web_server_mgr->tid, NULL, DaemonRunWebServer, mgr->web_server_mgr);
    if (ret != 0) {
        ERROR("[DAEMON] create web_server thread failed.(errno:%d, %s)\n", errno, strerror(errno));
        return -1;
    }
    INFO("[DAEMON] create web_server thread success.\n");

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
    ret = pthread_create(&mgr->rest_server_mgr->tid, NULL, DaemonRunRestServer, mgr->rest_server_mgr);
    if (ret != 0) {
        ERROR("[DAEMON] create rest api server thread failed.(errno:%d, %s)\n", errno, strerror(errno));
        return -1;
    }
    INFO("[DAEMON] create rest api server thread success.\n");

    return 0;
}

void destroy_daemon_threads(ResourceMgr *mgr)
{
    if (mgr == NULL) {
        return;
    }

    if (mgr->ingressMgr != NULL && mgr->ingressMgr->tid != 0) {
        pthread_cancel(mgr->ingressMgr->tid);
        pthread_join(mgr->ingressMgr->tid, NULL);
    }

    if (mgr->egressMgr != NULL && mgr->egressMgr->tid != 0) {
        pthread_cancel(mgr->egressMgr->tid);
        pthread_join(mgr->egressMgr->tid, NULL);
    }

    if (mgr->web_server_mgr != NULL && mgr->web_server_mgr->tid != 0) {
        pthread_cancel(mgr->web_server_mgr->tid);
        pthread_join(mgr->web_server_mgr->tid, NULL);
    }

    if (mgr->mmMgr != NULL && mgr->mmMgr->tid != 0) {
        pthread_cancel(mgr->mmMgr->tid);
        pthread_join(mgr->mmMgr->tid, NULL);
    }

    if (mgr->probe_mng != NULL && mgr->probe_mng->tid != 0) {
        pthread_cancel(mgr->probe_mng->tid);
        pthread_join(mgr->probe_mng->tid, NULL);
    }

    if (mgr->imdbMgr != NULL && mgr->imdbMgr->metrics_tid != 0) {
        pthread_cancel(mgr->imdbMgr->metrics_tid);
        pthread_join(mgr->imdbMgr->metrics_tid, NULL);
    }

    if (mgr->rest_server_mgr != NULL && mgr->rest_server_mgr->tid != 0) {
        pthread_cancel(mgr->rest_server_mgr->tid);
        pthread_join(mgr->rest_server_mgr->tid, NULL);
    }

    if (mgr->ctl_tid != 0) {
        pthread_cancel(mgr->ctl_tid);
        pthread_join(mgr->ctl_tid, NULL);
    }
}

int DaemonWaitDone(const ResourceMgr *mgr)
{
    // 1. wait ingress done
    pthread_join(mgr->ingressMgr->tid, NULL);

    // 2. wait egress done
    pthread_join(mgr->egressMgr->tid, NULL);

    // 3. wait web_server mng done
    pthread_join(mgr->web_server_mgr->tid, NULL);

    // 4. wait metadata_report done
    pthread_join(mgr->mmMgr->tid, NULL);

#if 0
    // 4. wait probe done
    for (int i = 0; i < mgr->probeMgr->probesNum; i++) {
        pthread_join(mgr->probeMgr->probes[i]->tid, NULL);
    }

    // 5. wait extend probe done
    for (int i = 0; i < mgr->extendProbeMgr->probesNum; i++) {
        pthread_join(mgr->extendProbeMgr->probes[i]->tid, NULL);
    }
#endif

    // 5. wait probe mng done
    pthread_join(mgr->probe_mng->tid, NULL);

    // 6. wait metric_write_logs done
    pthread_join(mgr->imdbMgr->metrics_tid, NULL);

    // 7. wait rest_api_server mng done
    pthread_join(mgr->rest_server_mgr->tid, NULL);

    // 8.wait ctl thread done
    pthread_join(mgr->ctl_tid, NULL);

    return 0;
}

