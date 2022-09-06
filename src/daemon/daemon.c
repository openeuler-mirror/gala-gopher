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

#include "server.h"
#include "daemon.h"

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

static int DaemonCheckProbeNeedStart(char *check_cmd, ProbeStartCheckType chkType)
{
    /* ret val: 1 need start / 0 no need start */
    if (!check_cmd || chkType != PROBE_CHK_CNT) {
        return 0;
    }

    int cnt = 0;
    FILE *fp = NULL;
    char data[MAX_COMMAND_LEN] = {0};
    fp = popen(check_cmd, "r");
    if (fp == NULL) {
        ERROR("popen error!(cmd = %s)\n", check_cmd);
        return 0;
    }

    if (fgets(data, sizeof(data), fp) != NULL) {
        cnt = atoi(data);
    }
    pclose(fp);

    return (cnt > 0);
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
#define __SYS_FS_BPF "/sys/fs/bpf"
    FILE *fp = NULL;
    char *pinPath;
    char cmd[MAX_COMMAND_LEN];

    cmd[0] = 0;
    pinPath = NULL;
    
    if (mgr->configMgr && mgr->configMgr->globalConfig) {
        pinPath = mgr->configMgr->globalConfig->bpfPinPath;
    }

    if (pinPath == NULL) {
        return;
    }
    if (strstr(pinPath, __SYS_FS_BPF) == NULL) {
        return;
    }
    
    (void)snprintf(cmd, MAX_COMMAND_LEN, "/usr/bin/rm -rf %s/*", pinPath);
    fp = popen(cmd, "r");
    if (fp != NULL) {
        (void)pclose(fp);
    }
    DEBUG("[DAEMON] clean data success[%s].\n", cmd);
}

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
            (void)pthread_join(probe->tid, NULL);

            INFO("[DAEMON] keeplive probe(%s) success.\n", probe->name);
            break;
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

int DaemonRun(const ResourceMgr *mgr)
{
    int ret;

    // 0. clean data
    CleanData(mgr);
    resouce_msg = mgr;

    // 1. start ingress thread
    ret = pthread_create(&mgr->ingressMgr->tid, NULL, DaemonRunIngress, mgr->ingressMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create ingress thread failed. errno: %d\n", errno);
        return -1;
    }
    INFO("[DAEMON] create ingress thread success.\n");

    // 2. start egress thread
    ret = pthread_create(&mgr->egressMgr->tid, NULL, DaemonRunEgress, mgr->egressMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create egress thread failed. errno: %d\n", errno);
        return -1;
    }
    INFO("[DAEMON] create egress thread success.\n");

    if (mgr->webServer) {
        // 3. start web_server thread
        ret = WebServerStartDaemon(mgr->webServer);
        if (ret != 0) {
            ERROR("[DAEMON] create web_server daemon failed. errno: %d\n", errno);
            return -1;
        }
        INFO("[DAEMON] create web_server daemon success.\n");
    }

    // 4. start metadata_report thread
    pthread_t meta_tid;
    ret = pthread_create(&meta_tid, NULL, DaemonRunMetadataReport, mgr->mmMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create metadata_report thread failed. errno: %d\n", ret);
        return -1;
    }
    INFO("[DAEMON] create metadata_report thread success.\n");

    // 5. start probe thread
    for (int i = 0; i < mgr->probeMgr->probesNum; i++) {
        Probe *_probe = mgr->probeMgr->probes[i];
        if (_probe->probeSwitch != PROBE_SWITCH_ON) {
            INFO("[DAEMON] probe %s switch is off, skip create thread for it.\n", _probe->name);
            continue;
        }
        ret = pthread_create(&mgr->probeMgr->probes[i]->tid, NULL, DaemonRunSingleProbe, _probe);
        if (ret != 0) {
            ERROR("[DAEMON] create probe thread failed. probe name: %s errno: %d\n", _probe->name, errno);
            return -1;
        }
        INFO("[DAEMON] create probe %s thread success.\n", mgr->probeMgr->probes[i]->name);
    }

    // 6. start extend probe thread
    INFO("[DAEMON] start extend probe(%u) thread.\n", mgr->extendProbeMgr->probesNum);
    for (int i = 0; i < mgr->extendProbeMgr->probesNum; i++) {
        ExtendProbe *_extendProbe = mgr->extendProbeMgr->probes[i];
        if (_extendProbe->probeSwitch == PROBE_SWITCH_OFF) {
            INFO("[DAEMON] extend probe %s switch is off, skip create thread for it.\n", _extendProbe->name);
            continue;
        }

        if (_extendProbe->probeSwitch == PROBE_SWITCH_AUTO) {
            ret = DaemonCheckProbeNeedStart(_extendProbe->startChkCmd, _extendProbe->chkType);
            if (ret != 1) {
                INFO("[DAEMON] extend probe %s start check failed, skip create thread for it.\n", _extendProbe->name);
                continue;
            }
        }

        ret = pthread_create(&mgr->extendProbeMgr->probes[i]->tid, NULL, DaemonRunSingleExtendProbe, _extendProbe);
        if (ret != 0) {
            ERROR("[DAEMON] create extend probe thread failed. probe name: %s errno: %d\n", _extendProbe->name, errno);
            return -1;
        }
        mgr->extendProbeMgr->probes[i]->is_running = 1;
        INFO("[DAEMON] create extend probe %s thread success.\n", mgr->extendProbeMgr->probes[i]->name);
    }

    // 7. start write metricsLogs thread
    pthread_t metrics_tid;
    ret = pthread_create(&metrics_tid, NULL, DaemonRunMetricsWriteLogs, mgr->imdbMgr);
    if (ret != 0) {
        ERROR("[DAEMON] create metrics_write_logs thread failed. errno: %d\n", errno);
        return -1;
    }
    INFO("[DAEMON] create metrics_write_logs thread success.\n");

    // 8. start CmdServer thread
    ret = pthread_create(&mgr->ctl_tid, NULL, CmdServer, NULL);
    if (ret != 0) {
        ERROR("[DAEMON] create cmd_server thread failed. errno: %d\n", errno);
        return -1;
    }
    INFO("[DAEMON] create cmd_server thread success.\n");

    // 9. create keeplive timer
    ret = DaemonCreateTimer((ResourceMgr *)mgr);
    if (ret != 0) {
        ERROR("[DAEMON] create keeplive timer failed. errno: %d\n", ret);
        return -1;
    }
    INFO("[DAEMON] create keeplive timer success.\n");

    return 0;
}

int DaemonWaitDone(const ResourceMgr *mgr)
{
    // 1. wait ingress done
    pthread_join(mgr->ingressMgr->tid, NULL);

    // 2. wait egress done
    pthread_join(mgr->egressMgr->tid, NULL);

    // 3. wait probe done
    for (int i = 0; i < mgr->probeMgr->probesNum; i++) {
        pthread_join(mgr->probeMgr->probes[i]->tid, NULL);
    }

    // 4. wait extend probe done
    for (int i = 0; i < mgr->extendProbeMgr->probesNum; i++) {
        pthread_join(mgr->extendProbeMgr->probes[i]->tid, NULL);
    }

    // 5.wait ctl thread done
    pthread_join(mgr->ctl_tid, NULL);

    return 0;
}

