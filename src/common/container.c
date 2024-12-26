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
 * Author: Mr.lu
 * Create: 2021-07-26
 * Description: container module
 ******************************************************************************/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sched.h>
#include <fcntl.h>
#include <regex.h>
#include "syscall.h"
#include "container.h"

#define ERR_MSG2 "not installed"
#define RUNNING "active (running)"

#define DOCKER_STATS_RUNNING "running"
#define DOCKER_STATS_RESTARTING "restarting"

#define DOCKER "docker"
#define ISULAD "isula"
#define CONTAINERD "crictl"

#define DRIVER_BTRFS "btrfs"
#define BTRFS_DOCKER_DIR "/var/lib/docker"

#define CONTAINERD_NAME_COMMAND "--output go-template --template='{{.status.metadata.name}}'"
#define CONTAINERD_PID_COMMAND "--output go-template --template='{{.info.pid}}'"
#define CONTAINERD_STATUS_COMMAND "--output go-template --template='{{.status.state}}'"
#define CONTAINERD_ID_COMMAND "%s ps -q | xargs %s inspect --output go-template --template='{{.info.pid}}, {{.status.id}}'"\
        "| /usr/bin/grep -w %u | /usr/bin/awk -F ', ' '{print $2}'"
#define CONTAINERD_POD_COMMAND "--output go-template --template='{{index .status.labels \"io.kubernetes.pod.name\"}}'"
#define CONTAINERD_PODID_COMMAND "--output go-template --template='{{index .status.labels \"io.kubernetes.pod.uid\"}}'"
#define CONTAINERD_POD_LABELS_COMMAND "--output go-template --template='{{json .status.labels}}'"
#define CONTAINERD_MERGED_COMMAND "mount | grep %s | grep rootfs | awk '{print $3}'"
#define CONTAINERD_IP_CMD "%s ps | grep %s | awk '{print $NF}' | xargs %s inspectp --output go-template --template='{{.status.network.ip}}'"
#define CONTAINERD_LIST_CONTAINER_COMMAND "%s ps -q | xargs  %s inspect --output go-template "\
    "--template='{{.status.id}}, {{index .status.labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' 2>/dev/null"
#define CONTAINERD_LIST_COUNT_COMMAND "%s ps -q | xargs  %s inspect --output go-template "\
        "--template='{{.status.id}}, {{index .status.labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' | wc -l"
#define CONTAINERD_IMAGE_COMMAND " --output go-template --template='{{.status.image.image}}'"

#define DOCKER_NAME_COMMAND "--format '{{.Name}}'"
#define DOCKER_PID_COMMAND "--format '{{.State.Pid}}'"
#define DOCKER_STATUS_COMMAND "--format '{{.State.Status}}'"
#define DOCKER_ID_COMMAND "%s ps -q | xargs %s inspect --format '{{.State.Pid}}, {{.Id}}' "\
        "| /usr/bin/grep -w %u | /usr/bin/awk -F ', ' '{print $2}'"
#define DOCKER_POD_COMMAND "--format '{{index .Config.Labels \"io.kubernetes.pod.name\"}}'"
#define DOCKER_PODID_COMMAND "--format '{{index .Config.Labels \"io.kubernetes.pod.uid\"}}'"
#define DOCKER_POD_LABELS_COMMAND "--format '{{json .Config.Labels}}'"
#define DOCKER_MERGED_COMMAND "--format '{{.GraphDriver.Data.MergedDir}}'"
#define DOCKER_IP_CMD "--format '{{ .NetworkSettings.IPAddress }}' 2>/dev/null"
#define DOCKER_LIST_CONTAINER_COMMAND "%s ps -q | xargs  %s inspect --format "\
    "'{{.Id}}, {{index .Config.Labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' 2>/dev/null"
#define DOCKER_LIST_COUNT_COMMAND "%s ps -q | xargs  %s inspect --format "\
        "'{{.Id}}, {{index .Config.Labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' | wc -l"
#define DOCKER_IMAGE_COMMAD "--format {{.Config.Image}}"

#define DOCKER_COUNT_COMMAND "ps | /usr/bin/awk 'NR > 1 {print $1}' | /usr/bin/wc -l"
#define DOCKER_PS_COMMAND "ps | /usr/bin/awk 'NR > 1 {print $1}'"


#define DOCKER_NETNS_COMMAND "/usr/bin/ls -l /proc/%u/ns/net | /usr/bin/awk -F '[' '{print $2}' "\
        "| /usr/bin/awk -F ']' '{print $1}'"
#define DOCKER_CGP_COMMAND "/usr/bin/ls -l /proc/%u/ns/cgroup | /usr/bin/awk -F '[' '{print $2}' "\
        "| /usr/bin/awk -F ']' '{print $1}'"
#define DOCKER_MNTNS_COMMAND "/usr/bin/ls -l /proc/%u/ns/mnt | /usr/bin/awk -F '[' '{print $2}' "\
        "| /usr/bin/awk -F ']' '{print $1}'"

#define DOCKER_DRIVER_COMMAND "%s info -f '{{ .Driver }}'"
#define DOCKER_BTRFS_SUBVOL_COMMAND "cat /proc/%u/mounts"

#define PROC_ROOT_COMMAND "/proc/%u/root"

#define PLDD_LIB_COMMAND "cat /proc/%u/maps 2>/dev/null | grep \"%s[^a-zA-Z]\" | awk 'NR==1{print $6}'"

// cgroupdriver=cgroupfs
#define KUBEPODS_PREFIX_CGRPFS    "/kubepods/"
#define DOCKER_PREFIX_CGRPFS      "/docker/"
#define PODID_PREFIX_CGRPFS       "/pod"
#define CONTAINERD_PREFIX_CGRPFS  "/kubepods-"
#define PODID_CONTAINERD_PREFIX_CGRPFS "-pod"
#define POD_CONTAINERD_DELIM_CGRPFS "slice/cri-containerd:"
#define CGRP_PATH_CGRPFS ".*[a-z0-9]{12}$" // cgroup path end with "<con_id>""

// cgroupdriver=systemd
#define KUBEPODS_PREFIX_SYSTEMD   "/kubepods.slice/"
#define DOCKER_PREFIX_SYSTEMD     "/system.slice/docker-"
#define PODID_PREFIX_SYSTEMD      "-pod"
#define POD_DOCKER_DELIM_SYSTEMD  "slice/docker-"
#define POD_CONTAINERD_DELIM_SYSTEMD "slice/cri-containerd-"
#define CGRP_PATH_SYSTEMD ".*[a-z0-9]{12}\\.scope$" // cgroup path end with "<con_id>.scope"

static char *current_docker_command = NULL;
static char current_docker_command_chroot[COMMAND_LEN];
static char current_docker_driver[CONTAINER_DRIVER_LEN] = {0};

static bool __is_docker_running(const char *docker_command)
{
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    FILE *f;
    bool is_running;

    is_running = false;
    (void)snprintf(command, COMMAND_LEN, "%s ps 2>/dev/null", docker_command);
    f = popen_chroot(command, "r");
    if (f == NULL) {
        return false;
    }

    while (!feof(f)) {
        (void)memset(line, 0, LINE_BUF_LEN);
        /* "docker/isula/crictl ps" has stdout means docker/isulad/containerd is running */
        if (fgets(line, LINE_BUF_LEN, f) != NULL) {
            is_running = true;
            current_docker_command = (char *)docker_command;
            goto out;
        }
    }

out:
    (void)pclose(f);
    return is_running;
}

static bool __is_dockerd()
{
    return __is_docker_running(DOCKER);
}

static bool __is_isulad()
{
    return __is_docker_running(ISULAD);
}

static bool __is_containerd()
{
    return __is_docker_running(CONTAINERD);
}

static const char *get_current_command()
{
    if (current_docker_command) {
        return (const char *)current_docker_command;
    }

    (void)__is_dockerd();
    (void)__is_isulad();
    (void)__is_containerd();

    return (const char *)current_docker_command;
}

static const char *get_current_command_chroot(void)
{
    if (current_docker_command_chroot[0] != 0) {
        return (const char *)current_docker_command_chroot;
    }

    return get_cmd_chroot(get_current_command(), current_docker_command_chroot, COMMAND_LEN);
}

static const char *get_docker_driver()
{
    FILE *f;
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    command[0] = 0;
    (void)snprintf(command, sizeof(command), DOCKER_DRIVER_COMMAND, DOCKER);
    f = popen_chroot(command, "r");
    if (!f) {
        return NULL;
    }

    line[0] = 0;
    if (!fgets(line, sizeof(line), f)) {
        (void)pclose(f);
        return NULL;
    }
    SPLIT_NEWLINE_SYMBOL(line);
    (void)snprintf(current_docker_driver, sizeof(current_docker_driver), "%s", line);

    (void)pclose(f);
    return (const char *)current_docker_driver;
}

static const char *get_current_driver(void)
{
    if (*current_docker_driver != '\0') {
        return (const char *)current_docker_driver;
    }

    if (!current_docker_command) {
        return NULL;
    }

    // Currently support docker, other container runtimes can be expanded here.
    if (strcmp(current_docker_command, DOCKER) == 0) {
        return get_docker_driver();
    } else {
        return NULL;
    }
}

static int __get_container_count(const char *command_s)
{
    int container_num = 0;
    char line[LINE_BUF_LEN];
    char command[COMMAND_LEN];

    container_num = 0;
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, "%s %s", command_s, DOCKER_COUNT_COMMAND);

    if (exec_cmd_chroot((const char *)command, line, LINE_BUF_LEN) < 0) {
        return -1;
    }

    container_num = atoi((const char *)line);
    return container_num;
}

static int __get_containers_id(container_tbl* cstbl, const char *command_s)
{
    char line[LINE_BUF_LEN];
    FILE *f = NULL;
    int index, ret;
    container_info *p;
    char command[COMMAND_LEN];

    p = cstbl->cs;
    index = 0;
    (void)memset(command, 0, COMMAND_LEN);
    (void)snprintf(command, COMMAND_LEN, "%s %s", command_s, DOCKER_PS_COMMAND);
    f = popen_chroot(command, "r");
    if (f == NULL) {
        return -1;
    }

    ret = 0;
    while (!feof(f) && index < cstbl->num) {
        (void)memset(line, 0, LINE_BUF_LEN);
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            ret = -1;
            goto out;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        (void)memcpy(p->abbrContainerId, line, CONTAINER_ABBR_ID_LEN);
        p->abbrContainerId[CONTAINER_ABBR_ID_LEN] = 0;
        p++;
        index++;
    }

out:
    (void)pclose(f);
    return ret;
}

static void __containers_status(container_info* container, const char *status)
{
    if (strstr(status, DOCKER_STATS_RUNNING) != NULL) {
        container->status = CONTAINER_STATUS_RUNNING;
        return;
    }

    if (strstr(status, DOCKER_STATS_RESTARTING) != NULL) {
        container->status = CONTAINER_STATUS_RESTARTING;
        return;
    }

    container->status = CONTAINER_STATUS_STOP;
}

static int __get_containers_status(container_tbl* cstbl, const char *command_s)
{
    char line[LINE_BUF_LEN];
    char command[COMMAND_LEN];
    int index;
    container_info *p;

    p = cstbl->cs;
    index = 0;
    for (index = 0; index < cstbl->num; index++) {
        command[0] = 0;
        line[0] = 0;

        if (__is_containerd()) {
            (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                    get_current_command(), CONTAINERD_STATUS_COMMAND, p->abbrContainerId);
        } else {
            (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                    command_s, p->abbrContainerId, DOCKER_STATUS_COMMAND);
        }

        if (!exec_cmd_chroot((const char *)command, line, LINE_BUF_LEN)) {
            __containers_status(p, line);
            p++;
        }
    }
    return 0;
}

static int __get_container_name(const char *abbr_container_id, char name[], unsigned int len)
{
    char command[COMMAND_LEN];

    if (!get_current_command()) {
        return -1;
    }

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                get_current_command(), CONTAINERD_NAME_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                get_current_command(), abbr_container_id, DOCKER_NAME_COMMAND);
    }

    return exec_cmd_chroot((const char *)command, name, len);
}

static int __get_container_pid(const char *abbr_container_id, unsigned int *pid)
{
    char line[LINE_BUF_LEN];
    char command[COMMAND_LEN];

    if (!get_current_command()) {
        return -1;
    }

    command[0] = 0;
    line[0] = 0;

    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                get_current_command(), CONTAINERD_PID_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                get_current_command(), abbr_container_id, DOCKER_PID_COMMAND);
    }

    if (exec_cmd_chroot((const char *)command, line, LINE_BUF_LEN) < 0) {
        return -1;
    }

    *pid = (unsigned int)atoi((const char *)line);
    return 0;
}

static int __get_container_pod(const char *abbr_container_id, char pod[], unsigned int len)
{
    char command[COMMAND_LEN];

    if (!get_current_command()) {
        return -1;
    }
    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                get_current_command(), CONTAINERD_POD_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
                get_current_command(), abbr_container_id, DOCKER_POD_COMMAND);
    }

    if (exec_cmd_chroot((const char *)command, pod, len) < 0) {
        return -1;
    }

    if (strstr(pod, abbr_container_id) != NULL) {
        // There is no pod
        pod[0] = 0;
        return -1;
    }

    return 0;
}

static int __get_container_pod_labels(const char *abbr_container_id, char pod_labels[], unsigned int len)
{
    char command[COMMAND_LEN];

    if (!get_current_command()) {
        return -1;
    }
    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command(), CONTAINERD_POD_LABELS_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command(), abbr_container_id, DOCKER_POD_LABELS_COMMAND);
    }

    if (exec_cmd_chroot((const char *)command, pod_labels, len) < 0) {
        return -1;
    }
    return 0;
}

static unsigned int __get_pid_namespace(unsigned int pid, const char *namespace)
{
    char ns[LINE_BUF_LEN];
    char command[COMMAND_LEN];

    command[0] = 0;
    ns[0] = 0;
    (void)snprintf(command, COMMAND_LEN, namespace, pid);

    if (exec_cmd_chroot((const char *)command, ns, LINE_BUF_LEN) < 0) {
        return 0;
    }

    return (unsigned int)atoi((const char *)ns);
}

static container_tbl* __get_all_container(const char *command_s)
{
    int container_num;
    size_t size;
    container_tbl *cstbl;

    cstbl = NULL;
    container_num = __get_container_count(command_s);
    if (container_num <= 0) {
        goto out;
    }

    size = sizeof(container_tbl) + container_num * sizeof(container_info);
    cstbl = (container_tbl *)malloc(size);
    if (cstbl == NULL) {
        goto out;
    }

    (void)memset(cstbl, 0, size);
    cstbl->num = container_num;
    cstbl->cs = (container_info *)(cstbl + 1);

    if (__get_containers_id(cstbl, command_s) < 0) {
        (void)free(cstbl);
        cstbl = NULL;
        goto out;
    }
    (void)__get_containers_status(cstbl, command_s);
out:
    return cstbl;
}

container_tbl* get_all_container(void)
{
    if (!get_current_command()) {
        return 0;
    }

    return __get_all_container(get_current_command());
}

void free_container_tbl(container_tbl **pcstbl)
{
    free(*pcstbl);
    *pcstbl = NULL;
}

static int get_container_merged_path_general(const char *abbr_container_id, char *path, unsigned int len)
{
    char command[COMMAND_LEN];

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s %s", \
            CONTAINERD_MERGED_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s", \
            get_current_command(), abbr_container_id, DOCKER_MERGED_COMMAND);
    }

    return exec_cmd_chroot((const char *)command, path, len);
}

static int read_subvol_from_fs_mntops(const char *fs_mntops, char *subvol, unsigned int size)
{
    char *subvol_start, *subvol_end;
    unsigned int subvol_len;

    // subvol=<path>/btrfs/subvolumes/<uuid>, <path> may be null
#define __SUBVOL_KEYWORD "/btrfs/subvolumes/"
    subvol_start = strstr(fs_mntops, __SUBVOL_KEYWORD);
    if (!subvol_start) {
        return -1;
    }

    subvol_end = strchr(subvol_start, ',');
    if (!subvol_end) {
        subvol_end = subvol_start + strlen(subvol_start);
    }

    subvol_len = (unsigned int)(subvol_end - subvol_start);
    if (subvol_len == 0 || subvol_len >= size) {
        return -1;
    }
    memcpy(subvol, subvol_start, subvol_len);
    subvol[subvol_len] = '\0';
    return 0;
}

static int get_container_btrfs_subvol(unsigned int pid, char *subvol, unsigned int size)
{
    FILE *f;
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    char fs_file[PATH_LEN];
    char fs_type[PATH_LEN];
    char fs_mntops[PATH_LEN];
    char format[SSCANF_FORMAT_LEN];
    int ret;

    command[0] = 0;
    (void)snprintf(command, sizeof(command), DOCKER_BTRFS_SUBVOL_COMMAND, pid);
    f = popen_chroot(command, "r");
    if (!f) {
        return -1;
    }

    (void)snprintf(format, sizeof(format), "%%*s %%%lus %%%lus %%%lus",
                   sizeof(fs_file) - 1, sizeof(fs_type) - 1,
                   sizeof(fs_mntops) - 1);
    while (!feof(f)) {
        line[0] = 0;
        if (fgets(line, sizeof(line), f) == NULL) {
            break;
        }
        fs_file[0] = 0;
        fs_type[0] = 0;
        fs_mntops[0] = 0;
        ret = sscanf(line, format, fs_file, fs_type, fs_mntops);
        if (ret != 3) {
            break;
        }
        if (strcmp(fs_file, "/") != 0) {
            continue;
        }
        if (strcmp(fs_type, DRIVER_BTRFS) != 0) {
            break;
        }
        if (read_subvol_from_fs_mntops(fs_mntops, subvol, size)) {
            break;
        }
        (void)pclose(f);
        return 0;
    }

    (void)pclose(f);
    return -1;
}

static int get_container_merged_path_btrfs(const char *abbr_container_id, char *path, unsigned int len)
{
    unsigned int pid = 0;
    char *btrfs_root_dir = NULL;
    char btrfs_subvol[PATH_LEN];
    int ret;

    // Currently support docker, other container runtimes can be expanded here.
    if (strcmp(current_docker_command, DOCKER) == 0) {
        btrfs_root_dir = BTRFS_DOCKER_DIR;
    } else {
        return -1;
    }

    ret = __get_container_pid(abbr_container_id, &pid);
    if (ret || pid == 0) {
        return -1;
    }

    btrfs_subvol[0] = 0;
    ret = get_container_btrfs_subvol(pid, btrfs_subvol, sizeof(btrfs_subvol));
    if (ret) {
        return -1;
    }
    ret = snprintf(path, len, "%s%s", btrfs_root_dir, btrfs_subvol);
    if (ret < 0 || ret >= len) {
        return -1;
    }

    return 0;
}

int get_container_root_path(const char *abbr_container_id, char *path, unsigned int len)
{
    unsigned int pid = 0;
    int ret;

    ret = __get_container_pid(abbr_container_id, &pid);
    if (ret || pid == 0) {
        return -1;
    }
    ret = snprintf(path, len, PROC_ROOT_COMMAND, pid);
    if (ret < 0 || ret >= len) {
        return -1;
    }

    return 0;
}

/*
parse string
[root@node2 ~]# docker inspect 92a7a60249cb | grep MergedDir | awk -F '"' '{print $4}'
                /var/lib/docker/overlay2/82c62b73874d9a17a78958d5e13af478b1185db6fa614a72e0871c1b7cd107f5/merged
*/
int get_container_merged_path(const char *abbr_container_id, char *path, unsigned int len)
{
    const char *current_driver = NULL;

    if (!get_current_command()) {
        return -1;
    }

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    path[0] = 0;
    current_driver = get_current_driver();
    if (current_driver && strcmp(current_driver, DRIVER_BTRFS) == 0) {
        return get_container_merged_path_btrfs(abbr_container_id, path, len);
    }

    return get_container_merged_path_general(abbr_container_id, path, len);
}

/* docker exec -it 92a7a60249cb [xxx] */
int exec_container_command(const char *abbr_container_id, const char *exec, char *buf, unsigned int len)
{
    char command[COMMAND_LEN];

    command[0] = 0;
    buf[0] = 0;

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    if (!get_current_command()) {
        return -1;
    }

    (void)snprintf(command, COMMAND_LEN, "%s exec -it %s %s", \
            get_current_command(), abbr_container_id, exec);

    return exec_cmd_chroot((const char *)command, buf, len);
}

static enum cgrp_driver_t get_cgroup_drvier(const char *cgrp_path)
{
    if (strncmp(cgrp_path, KUBEPODS_PREFIX_CGRPFS, strlen(KUBEPODS_PREFIX_CGRPFS)) == 0 ||
        strncmp(cgrp_path, DOCKER_PREFIX_CGRPFS, strlen(DOCKER_PREFIX_CGRPFS)) == 0 ||
        strncmp(cgrp_path, CONTAINERD_PREFIX_CGRPFS, strlen(CONTAINERD_PREFIX_CGRPFS)) == 0 ) {
        return CGRP_DRIVER_CGRPFS;
    }

    if (strncmp(cgrp_path, KUBEPODS_PREFIX_SYSTEMD, strlen(KUBEPODS_PREFIX_SYSTEMD)) == 0 ||
        strncmp(cgrp_path, DOCKER_PREFIX_SYSTEMD, strlen(DOCKER_PREFIX_SYSTEMD)) == 0) {
        return CGRP_DRIVER_SYSTEMD;
    }

    return CGRP_DRIVER_UNKNOWN;
}

static char __chk_cgrp_path_pattern(const char *conf_pattern, const char *target)
{
    int status;
    regex_t re;

    if (target[0] == 0 || conf_pattern[0] == 0) {
        return 0;
    }

    if (regcomp(&re, conf_pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        return 0;
    }

    status = regexec(&re, target, 0, NULL, 0);
    regfree(&re);

    return (status == 0) ? 1 : 0;
}

static enum id_ret_t get_pod_container_id_by_type(const char *cgrp_path, char *pod_id, char *con_id, enum cgrp_driver_t type)
{
    enum id_ret_t ret;
    int full_path_len;
    char *p, *kube_prefix, *podid_prefix, *docker_prefix;
    char delim;
    int i,j;
    bool is_containerd = false;

    if (strstr(cgrp_path, "containerd") != NULL) {
        is_containerd = true;
    }

    if (type == CGRP_DRIVER_CGRPFS) {
        /* cgroupf driver is cgroupfs
         * k8s scenario, cgrp_path is like: /kubepods/besteffort/pod<pod_id>/<con_id>
         * docker scenario, cgrp_path is like: /docker/<con_id>
         * containerd scenario, cgrp_path is like /kubepods-burstable-pod<pod_id>.slice:cri-containerd:<con_id>
         */
        if (!__chk_cgrp_path_pattern(CGRP_PATH_CGRPFS, cgrp_path)) {
            return ID_FAILED;
        }
        docker_prefix = DOCKER_PREFIX_CGRPFS;
        if (is_containerd) {
            kube_prefix = CONTAINERD_PREFIX_CGRPFS;
            podid_prefix = PODID_CONTAINERD_PREFIX_CGRPFS;
            delim = '.';
        } else {
            kube_prefix = KUBEPODS_PREFIX_CGRPFS;
            podid_prefix = PODID_PREFIX_CGRPFS;
            delim = '/';
        }
    } else if (type == CGRP_DRIVER_SYSTEMD) {
        /* cgroupf driver is systemd
         * k8s scenario, cgrp_path is like: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<pod_id>.slice/docker-<con_id>.scope
         * docker scenario, cgrp_path is like: /system.slice/docker-<con_id>.scope
         * containerd scenario, cgrp_path is like /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<pod_id>.slice/cri-containerd-<con_id>.scope
         */
        if (!__chk_cgrp_path_pattern(CGRP_PATH_SYSTEMD, cgrp_path)) {
            return ID_FAILED;
        }
        kube_prefix = KUBEPODS_PREFIX_SYSTEMD;
        podid_prefix = PODID_PREFIX_SYSTEMD;
        docker_prefix = DOCKER_PREFIX_SYSTEMD;
        delim = '.';
    } else {
        return ID_FAILED;
    }

    full_path_len = strlen(cgrp_path);
    if (strstr(cgrp_path, kube_prefix) != NULL) {
        p = strstr(cgrp_path, podid_prefix);
        if (p == NULL) {
            return ID_FAILED;
        }
        p += strlen(podid_prefix);
        i = 0;
        while (i < POD_ID_LEN && i + p - cgrp_path < full_path_len) {
            if (p[i] == delim) {
                pod_id[i++] = 0;
                break;
            }
            // format pod id to xxxx-xxxx-xxxxx
            (p[i] == '_') ? (pod_id[i] = '-') : (pod_id[i] = p[i]);
            i++;
        }
        pod_id[POD_ID_LEN] = 0;
        if (strlen(pod_id) == POD_ID_LEN) {
            i++;         // reach the '/' or '.'
        }
        if (type == CGRP_DRIVER_SYSTEMD) {
            if (is_containerd) {
                i += strlen(POD_CONTAINERD_DELIM_SYSTEMD);
            } else {
                i += strlen(POD_DOCKER_DELIM_SYSTEMD);
            }
        } else if (type == CGRP_DRIVER_CGRPFS) {
            if (is_containerd) {
                i += strlen(POD_CONTAINERD_DELIM_CGRPFS);
            }
        }
        if (i + p - cgrp_path >= full_path_len) {
            return ID_POD_ONLY;
        }
        ret = ID_CON_POD;
    } else if ((p = strstr(cgrp_path, docker_prefix)) != NULL) {
        i = strlen(docker_prefix);
        (void)snprintf(pod_id, POD_ID_LEN + 1, "%s", FAKE_POD_ID);
        ret = ID_CON_ONLY;
    } else {
        return ID_FAILED;
    }

    // get container id
    p += i;
    j = 0;
    while (j < CONTAINER_ABBR_ID_LEN && j + p - cgrp_path < full_path_len) {
        if (p[j] == delim) {
            con_id[j++] = 0;
            break;
        }
        con_id[j] = p[j];
        j++;
    }

    if (j < CONTAINER_ABBR_ID_LEN) {
        // Failed to get cpucg inode of container cleanup.
        // /system.slice/docker-cleanup.service
        return ID_FAILED;
    }

    con_id[CONTAINER_ABBR_ID_LEN] = 0;
    return ret;
}

enum id_ret_t get_pod_container_id(const char *cgrp_path, char *pod_id, char *con_id)
{
    if (!cgrp_path) {
        return ID_FAILED;
    }

    return get_pod_container_id_by_type(cgrp_path, pod_id, con_id, get_cgroup_drvier(cgrp_path));
}

#define __PROC_CPUSET           "/proc/%s/cpuset"
static int __is_container_id(char *container_id)
{
    int len = strlen(container_id);
    if (len == 0 || len > CONTAINER_ID_LEN) {
        return 0;
    }

    for (int i = 0; i < len; i++) {
        if (*(container_id + i) >= '0' && *(container_id + i) <= '9') {
            continue;
        } else if (*(container_id + i) >= 'A' && *(container_id + i) <= 'F') {
            continue;
        } else if (*(container_id + i) >= 'a' && *(container_id + i) <= 'f') {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

int get_container_id_by_pid_cpuset(const char *pid, char *container_id, unsigned int buf_len)
{
    FILE *f = NULL;
    char proc_cpuset[PATH_LEN];
    char cpuset_buf[MAX_CGRP_PATH];
    char pod_id[POD_ID_LEN + 1];

    if (buf_len <= CONTAINER_ABBR_ID_LEN) {
        return -1;
    }

    proc_cpuset[0] = 0;
    (void)snprintf(proc_cpuset, PATH_LEN, __PROC_CPUSET, pid);
    f = fopen(proc_cpuset, "r");
    if (!f) {
        return -1;
    }
    cpuset_buf[0] = 0;
    if (fgets(cpuset_buf, sizeof(cpuset_buf), f) == NULL) {
        (void)fclose(f);
        return -1;
    }
    (void)fclose(f);
    SPLIT_NEWLINE_SYMBOL(cpuset_buf);

    pod_id[0] = 0;
    container_id[0] = 0;
    if (get_pod_container_id(cpuset_buf, pod_id, container_id) == ID_FAILED) {
        container_id[0] = 0;
        return 0;
    }

    if (!__is_container_id(container_id)) {
        container_id[0] = 0;
        return 0;
    }

    container_id[CONTAINER_ABBR_ID_LEN] = 0;
    return 0;
}

int get_elf_path(unsigned int pid, char elf_path[], int max_path_len, const char *comm)
{
    char cmd[COMMAND_LEN] = {0};
    char elf_relative_path[PATH_LEN] = {0};
    char container_id[CONTAINER_ABBR_ID_LEN + 1] = {0};
    char container_path[PATH_LEN] = {0};
    char tmp_path[PATH_LEN] = {0};
    char pid_str[INT_LEN];

    // 1. get elf_path
    (void)snprintf(cmd, COMMAND_LEN, PLDD_LIB_COMMAND, pid, comm);
    if (exec_cmd((const char *)cmd, elf_relative_path, PATH_LEN) < 0) {
        return CONTAINER_NOTOK;
    }

    // If the container id is not found, it means that gaussdb is a process on the host
    pid_str[0] = 0;
    (void)snprintf(pid_str, sizeof(pid_str), "%d", pid);
    if ((get_container_id_by_pid_cpuset(pid_str, container_id, CONTAINER_ABBR_ID_LEN + 1) == 0) &&
        (container_id[0] != 0)) {
        if (get_container_root_path(container_id, container_path, PATH_LEN) < 0) {
            fprintf(stderr, "get container %s root path failed\n", container_id);
            return CONTAINER_ERR;
        }
        (void)snprintf(tmp_path, PATH_LEN, "%s%s", container_path, elf_relative_path);
    } else {
        (void)snprintf(tmp_path, PATH_LEN, "%s", elf_relative_path);
    }

    convert_to_host_path(elf_path, tmp_path, max_path_len);

    if (elf_path[0] != '\0') {
        if (access(elf_path, R_OK) != 0) {
            fprintf(stderr, "File %s not exist or not readable!\n", elf_path);
            return CONTAINER_ERR;
        }
    }

    return CONTAINER_OK;
}

int get_elf_path_by_con_id(char *container_id, char elf_path[], int max_path_len, const char *comm)
{
    char cmd[COMMAND_LEN] = {0};
    char elf_relative_path[PATH_LEN] = {0};
    char container_path[PATH_LEN] = {0};
    unsigned int pid;
    int ret;

    if (container_id == NULL || container_id[0] == 0) {
        return CONTAINER_ERR;
    }

    ret = get_container_pid(container_id, &pid);
    if (ret) {
        return CONTAINER_ERR;
    }

    (void)snprintf(cmd, COMMAND_LEN, PLDD_LIB_COMMAND, pid, comm);
    if (exec_cmd((const char *)cmd, elf_relative_path, PATH_LEN) < 0) {
        return CONTAINER_NOTOK;
    }

    if (get_container_root_path(container_id, container_path, PATH_LEN) < 0) {
        return CONTAINER_ERR;
    }

    (void)snprintf(elf_path, max_path_len, "%s%s", container_path, elf_relative_path);

    if (elf_path[0] != '\0') {
        if (access(elf_path, R_OK) != 0) {
            return CONTAINER_ERR;
        }
    }

    return CONTAINER_OK;
}

#define __PID_GRP_KIND_DIR "/usr/bin/cat /proc/%u/cgroup | /usr/bin/grep -w %s"
#define __PID_GRP_DIR "/proc/%u/cgroup"
int get_cgp_dir_by_pid(unsigned int pid, const char *kind, char dir[], unsigned int dir_len)
{
    char command[COMMAND_LEN];
    char proc[PATH_LEN];
    char line[LINE_BUF_LEN];
    int ret = 0;
    char *substr1, *substr2;

    command[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __PID_GRP_KIND_DIR, pid, kind);

    proc[0] = 0;
    (void)snprintf(proc, PATH_LEN, __PID_GRP_DIR, pid);
    if (access(proc, 0) != 0) {
        return -1;
    }

    ret = exec_cmd((const char *)command, line, LINE_BUF_LEN);
    if (ret != 0) {
        dir[0] = 0;
        return ret;
    }

    substr1 = strstr(line, ":");
    if (substr1) {
        substr2 = strstr((substr1 + 1), ":");
        if (substr2) {
            snprintf(dir, dir_len, "%s", (substr2 + 1));
            return 0;
        }
    }
    return -1;
}

#define __CONTAINER_GRP_KIND_DIR "/sys/fs/cgroup/%s%s"
static int __get_container_cgpdir(const char *abbr_container_id, const char *kind, char dir[], unsigned int dir_len)
{
    unsigned int pid;
    char kind_dir[CG_PATH_LEN];

    if (__get_container_pid(abbr_container_id, &pid) < 0) {
        return -1;
    }

    kind_dir[0] = 0;
    if (get_cgp_dir_by_pid(pid, kind, kind_dir, CG_PATH_LEN) < 0) {
        return -1;
    }

    (void)snprintf(dir, dir_len, __CONTAINER_GRP_KIND_DIR, kind, kind_dir);
    return 0;
}


#define __STAT_INODE "/usr/bin/stat --format=%%i %s"
static int __get_fullpath_inode(const char *full_path, unsigned int *inode)
{
    char command[CG_PATH_LEN];
    char inode_s[CG_PATH_LEN];

    if (access(full_path, 0) != 0) {
        fprintf(stderr, "access path failed %s\n", full_path);
        return -1;
    }

    command[0] = 0;
    inode_s[0] = 0;
    (void)snprintf(command, CG_PATH_LEN, __STAT_INODE, full_path);

    if (exec_cmd_chroot((const char *)command, inode_s, CG_PATH_LEN) < 0) {
        fprintf(stderr, "get inode failed %s\n", full_path);
        return -1;
    }

    *inode = (unsigned int)atoi((const char *)inode_s);
    return 0;
}

#define CGROUP_SUBSYS_CPUACCT   "cpu,cpuacct"
#define CGROUP_SUBSYS_MEMORY    "memory"
#define CGROUP_SUBSYS_PIDS      "pids"
#define CGROUP_SUBSYS_NETCLS    "net_cls,net_prio"
int get_container_cpucg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_cgpdir(abbr_container_id, CGROUP_SUBSYS_CPUACCT, dir, dir_len);
}

int get_container_memcg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_cgpdir(abbr_container_id, CGROUP_SUBSYS_MEMORY, dir, dir_len);
}

int get_container_pidcg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_cgpdir(abbr_container_id, CGROUP_SUBSYS_PIDS, dir, dir_len);
}

int get_container_netcg_dir(const char *abbr_container_id, char dir[], unsigned int dir_len)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_cgpdir(abbr_container_id, CGROUP_SUBSYS_NETCLS, dir, dir_len);
}

int get_container_cpucg_inode(const char *abbr_container_id, unsigned int *inode)
{
    char cpucg_dir[CG_PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    cpucg_dir[0] = 0;
    if (get_container_cpucg_dir(abbr_container_id, cpucg_dir, CG_PATH_LEN) < 0) {
        return -1;
    }

    return __get_fullpath_inode((const char *)cpucg_dir, inode);
}

int get_container_memcg_inode(const char *abbr_container_id, unsigned int *inode)
{
    char memcg_dir[CG_PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    memcg_dir[0] = 0;
    if (get_container_memcg_dir(abbr_container_id, memcg_dir, CG_PATH_LEN) < 0) {
        return -1;
    }

    return __get_fullpath_inode((const char *)memcg_dir, inode);
}

int get_container_pidcg_inode(const char *abbr_container_id, unsigned int *inode)
{
    char pidcg_dir[CG_PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    pidcg_dir[0] = 0;
    if (get_container_pidcg_dir(abbr_container_id, pidcg_dir, CG_PATH_LEN) < 0) {
        return -1;
    }

    return __get_fullpath_inode((const char *)pidcg_dir, inode);
}

#define __PROC_NS_DIR "/proc/%u/ns"

int get_container_netns_id(const char *abbr_container_id, unsigned int *id)
{
    unsigned int pid;
    char proc[PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    if (__get_container_pid(abbr_container_id, &pid) < 0) {
        return -1;
    }

    proc[0] = 0;
    (void)snprintf(proc, PATH_LEN, __PROC_NS_DIR, pid);
    if (access(proc, 0) != 0) {
        return -1;
    }

    *id = __get_pid_namespace(pid, DOCKER_NETNS_COMMAND);
    return 0;
}

int get_proc_netns_id(const unsigned int pid, unsigned int *id)
{
    *id = __get_pid_namespace(pid, DOCKER_NETNS_COMMAND);
    return 0;
}

int get_container_mntns_id(const char *abbr_container_id, unsigned int *id)
{
    unsigned int pid;
    char proc[PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    if (__get_container_pid(abbr_container_id, &pid) < 0) {
        return -1;
    }

    proc[0] = 0;
    (void)snprintf(proc, PATH_LEN, __PROC_NS_DIR, pid);
    if (access(proc, 0) != 0) {
        return -1;
    }

    *id = __get_pid_namespace(pid, DOCKER_MNTNS_COMMAND);
    return 0;
}

int get_container_pid(const char *abbr_container_id, unsigned int *pid)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_pid(abbr_container_id, pid);
}

int get_container_name(const char *abbr_container_id, char name[], unsigned int len)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_name(abbr_container_id, name, len);
}

int get_container_pod(const char *abbr_container_id, char pod[], unsigned int len)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_pod(abbr_container_id, pod, len);
}

int get_container_pod_id(const char *abbr_container_id, char pod_id[], unsigned int len)
{
    char command[COMMAND_LEN];

    if (!get_current_command()) {
        return -1;
    }

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command(), CONTAINERD_PODID_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command(), abbr_container_id, DOCKER_PODID_COMMAND);
    }

    int ret = exec_cmd_chroot((const char *)command, pod_id, len);
    if (ret) {
        pod_id[0] = 0;
    }

    return ret;
}

int get_container_pod_labels(const char *abbr_container_id, char pod_labels[], unsigned int len)
{
    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }
    return __get_container_pod_labels(abbr_container_id, pod_labels, len);
}

int get_pod_ip(const char *abbr_container_id, char *pod_ip_str, int len)
{
    char command[CHROOT_COMMAND_LEN] = {0};

    if (!get_current_command()) {
        return -1;
    }

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, CONTAINERD_IP_CMD,
            get_current_command_chroot(), abbr_container_id, get_current_command_chroot());
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command_chroot(), abbr_container_id, DOCKER_IP_CMD);
    }

    int ret = exec_cmd((const char *)command, pod_ip_str, len);

    if (ret) {
        pod_ip_str[0] = 0;
    }

    return ret;
}

static int __list_containers_count_by_pod_id(const char *pod_id)
{
    char command[CHROOT_COMMAND_LEN];
    char line[INT_LEN];

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, sizeof(command), CONTAINERD_LIST_COUNT_COMMAND,
            get_current_command_chroot(), get_current_command_chroot(), pod_id);
    } else {
        (void)snprintf(command, sizeof(command), DOCKER_LIST_COUNT_COMMAND,
            get_current_command_chroot(), get_current_command_chroot(), pod_id);
    }

    line[0] = 0;
    int ret = exec_cmd((const char *)command, line, INT_LEN);
    if (ret) {
        return 0;
    }
    return atoi(line);
}

static int __list_containers_by_pod_id(const char *pod_id, container_tbl *cstbl)
{
    int index = 0;
    char command[CHROOT_COMMAND_LEN];
    char line[LINE_BUF_LEN];
    FILE *f = NULL;
    container_info *p;
    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, CHROOT_COMMAND_LEN, CONTAINERD_LIST_CONTAINER_COMMAND,
            get_current_command_chroot(), get_current_command_chroot(), pod_id);
    } else {
        (void)snprintf(command, CHROOT_COMMAND_LEN, DOCKER_LIST_CONTAINER_COMMAND,
            get_current_command_chroot(), get_current_command_chroot(), pod_id);
    }

    f = popen(command, "r");
    if (f == NULL) {
        return -1;
    }
    while (!feof(f) && (index < cstbl->num)) {
        p = cstbl->cs + index;
        line[0] = 0;
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            break;
        }
        SPLIT_NEWLINE_SYMBOL(line);
        (void)snprintf(p->abbrContainerId, CONTAINER_ABBR_ID_LEN + 1, "%s", line);
        index++;
    }

    pclose(f);
    return 0;
}

container_tbl* list_containers_by_pod_id(const char *pod_id)
{
    int container_num;
    size_t size;
    container_tbl *cstbl;

    if (!get_current_command()) {
        return NULL;
    }

    if (pod_id == NULL || pod_id[0] == 0) {
        return NULL;
    }

    container_num = __list_containers_count_by_pod_id(pod_id);
    if (container_num <= 0) {
        return NULL;
    }

    size = sizeof(container_tbl) + container_num * sizeof(container_info);
    cstbl = (container_tbl *)malloc(size);
    if (cstbl == NULL) {
        return NULL;
    }

    (void)memset(cstbl, 0, size);
    cstbl->num = (unsigned int)container_num;
    cstbl->cs = (container_info *)(cstbl + 1);

    (void)__list_containers_by_pod_id(pod_id, cstbl);

    return cstbl;
}

static int __get_netns_fd(pid_t pid)
{
    const char *fmt = "/proc/%d/ns/net";
    char path[PATH_LEN];

    path[0] = 0;
    (void)snprintf(path, PATH_LEN, fmt, pid);
    return open(path, O_RDONLY);
}

static int __pidfd_open(pid_t pid, unsigned int flags)
{
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434     // System call # on most architectures
#endif
    return syscall(__NR_pidfd_open, pid, flags);
}

static int __set_netns_by_pid(pid_t pid)
{
    int ret;
    int fd = -1;
    u32 kern_version = 0;

    (void)get_kern_version(&kern_version);
    if (kern_version < KERNEL_VERSION(5, 3, 0)) {
        fd = __get_netns_fd(pid);
    } else {
        fd = __pidfd_open(pid, 0);
    }

    if (fd == -1) {
        ERROR("Get tgid(%d)'s pidfd failed.\n", pid);
        return -1;
    }
    ret = setns(fd, CLONE_NEWNET);
    (void)close(fd);
    return ret;
}

static int __set_netns_by_fd(int fd)
{
    return setns(fd, CLONE_NEWNET);
}

int enter_container_netns(const char *container_id)
{
    int ret;
    u32 pid;

    ret = get_container_pid(container_id, &pid);
    if (ret) {
        ERROR("[TCPPROBE]: Get container pid failed.(%s, ret = %d)\n", container_id, ret);
        return ret;
    }

    return __set_netns_by_pid((pid_t)pid);
}

int exit_container_netns(int netns_fd)
{
    return __set_netns_by_fd(netns_fd);
}

int enter_proc_netns(u32 pid)
{
    return __set_netns_by_pid((pid_t)pid);
}

int is_container_proc(u32 pid)
{
    char container_id[CONTAINER_ID_LEN + 1];
    char pid_str[INT_LEN];
    int ret;

    pid_str[0] = 0;
    container_id[0] = 0;
    (void)snprintf(pid_str, sizeof(pid_str), "%d", pid);
    ret = get_container_id_by_pid_cpuset(pid_str, container_id, sizeof(container_id));
    if (ret || container_id[0] == 0) {
        return 0;
    }

    return 1;
}

#define __CONTAINER_IMAGE_DELIM        '@'
#define __CONTAINER_IMAGE_SHA_PREFIX   "sha256:"
int get_container_image(const char *abbr_container_id, char image[], unsigned int image_len)
{
    char command[COMMAND_LEN];
    char orig_image[CONTAINER_IMAGE_LEN];
    char *ptr;
    unsigned int len;

    if (!get_current_command()) {
        return -1;
    }

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command(), CONTAINERD_IMAGE_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command(), abbr_container_id, DOCKER_IMAGE_COMMAD);
    }

    image[0] = 0;
    orig_image[0] = 0;
    if (exec_cmd_chroot((const char *)command, orig_image, image_len)) {
        return -1;
    }

    // format: sha256:<IMAGE_ID>, we only take the beginning part of IMAGE_ID
    if (strncmp(orig_image, __CONTAINER_IMAGE_SHA_PREFIX, strlen(__CONTAINER_IMAGE_SHA_PREFIX)) == 0) {
        ptr = orig_image + strlen(__CONTAINER_IMAGE_SHA_PREFIX);
        len = min(image_len, CONTAINER_IMAGE_ID_LEN + 1);
        snprintf(image, len, "%s", ptr);
        return 0;
    }

    // format: <IMAGE_NAME>@sha256:<IMAGE_ID>, we take the IMAGE_NAME
    ptr = strrchr(orig_image, __CONTAINER_IMAGE_DELIM);
    if (ptr) {
        int index = ptr - orig_image;
        if (index >= CONTAINER_IMAGE_LEN || index < 0) {
            return -1;
        }
        orig_image[index] = 0;
        snprintf(image, image_len, "%s", orig_image);
        return 0;
    }

    // format: <IMAGE_NAME>
    snprintf(image, image_len, "%s", orig_image);
    return 0;
}


