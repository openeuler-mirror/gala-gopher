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
#include "syscall.h"
#include "container.h"

#define ERR_MSG2 "not installe"
#define RUNNING "active (running)"

#define DOCKER_STATS_RUNNING "running"
#define DOCKER_STATS_RESTARTING "restarting"

#define DOCKER "docker"
#define ISULAD "isula"
#define CONTAINERD "crictl"


#define CONTAINERD_NAME_COMMAND "--output go-template --template='{{.status.metadata.name}}'"
#define CONTAINERD_PID_COMMAND "--output go-template --template='{{.info.pid}}'"
#define CONTAINERD_STATUS_COMMAND "--output go-template --template='{{.status.state}}'"
#define CONTAINERD_ID_COMMAND "%s ps -q | xargs %s inspect --output go-template --template='{{.info.pid}}, {{.status.id}}'"\
        "| /usr/bin/grep -w %u | /usr/bin/awk -F ', ' '{print $2}'"
#define CONTAINERD_POD_COMMAND "--output go-template --template='{{index .status.labels \"io.kubernetes.pod.name\"}}''"
#define CONTAINERD_PODID_COMMAND "--output go-template --template='{{index .status.labels \"io.kubernetes.pod.uid\"}}''"
#define CONTAINERD_MERGED_COMMAND "mount | grep %s | grep rootfs | awk '{print $3}'"
#define CONTAINERD_IP_CMD "%s ps | grep %s | awk '{print $NF}' | xargs %s inspectp --output go-template --template='{{.status.network.ip}}'"
#define CONTAINERD_LIST_CONTAINER_COMMAND "%s ps -q | xargs  %s inspect --output go-template "\
    "--template='{{.status.id}}, {{index .status.labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' 2>/dev/null"
#define CONTAINERD_LIST_COUNT_COMMAND "%s ps -q | xargs  %s inspect --output go-template "\
        "--template='{{.status.id}}, {{index .status.labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' | wc -l"

#define DOCKER_NAME_COMMAND "--format '{{.Name}}'"
#define DOCKER_PID_COMMAND "--format '{{.State.Pid}}'"
#define DOCKER_STATUS_COMMAND "--format '{{.State.Status}}'"
#define DOCKER_ID_COMMAND "%s ps -q | xargs %s inspect --format '{{.State.Pid}}, {{.Id}}' "\
        "| /usr/bin/grep -w %u | /usr/bin/awk -F ', ' '{print $2}'"
#define DOCKER_POD_COMMAND "--format '{{index .Config.Labels \"io.kubernetes.pod.name\"}}'"
#define DOCKER_PODID_COMMAND "--format '{{index .Config.Labels \"io.kubernetes.pod.uid\"}}'"
#define DOCKER_MERGED_COMMAND "--format '{{.GraphDriver.Data.MergedDir}}'"
#define DOCKER_IP_CMD "--format '{{ .NetworkSettings.IPAddress }}' 2>/dev/null"
#define DOCKER_LIST_CONTAINER_COMMAND "%s ps -q | xargs  %s inspect --format "\
    "'{{.Id}}, {{index .Config.Labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' 2>/dev/null"
#define DOCKER_LIST_COUNT_COMMAND "%s ps -q | xargs  %s inspect --format "\
        "'{{.Id}}, {{index .Config.Labels \"io.kubernetes.pod.uid\"}}' | /usr/bin/grep %s |  /usr/bin/awk -F ', ' '{print $1}' | wc -l"

#define DOCKER_COUNT_COMMAND "ps | /usr/bin/awk 'NR > 1 {print $1}' | /usr/bin/wc -l"
#define DOCKER_PS_COMMAND "ps | /usr/bin/awk 'NR > 1 {print $1}'"


#define DOCKER_NETNS_COMMAND "/usr/bin/ls -l /proc/%u/ns/net | /usr/bin/awk -F '[' '{print $2}' "\
        "| /usr/bin/awk -F ']' '{print $1}'"
#define DOCKER_CGP_COMMAND "/usr/bin/ls -l /proc/%u/ns/cgroup | /usr/bin/awk -F '[' '{print $2}' "\
        "| /usr/bin/awk -F ']' '{print $1}'"
#define DOCKER_MNTNS_COMMAND "/usr/bin/ls -l /proc/%u/ns/mnt | /usr/bin/awk -F '[' '{print $2}' "\
        "| /usr/bin/awk -F ']' '{print $1}'"

#define PLDD_LIB_COMMAND "pldd %u 2>/dev/null | grep \"%s\""

static char *current_docker_command = NULL;

#if 0
static bool __is_install_rpm(const char* command)
{
    char line[LINE_BUF_LEN];
    FILE *f;
    bool is_installed;

    is_installed = false;
    f = popen(command, "r");
    if (f == NULL) {
        return false;
    }

    (void)memset(line, 0, LINE_BUF_LEN);
    if (fgets(line, LINE_BUF_LEN, f) == NULL) {
        goto out;
    }

    if (strstr(line, ERR_MSG2) != NULL) {
        goto out;
    }

    is_installed = true;
out:
    (void)pclose(f);
    return is_installed;
}

static bool __is_service_running(const char* service)
{
    char line[LINE_BUF_LEN];
    FILE *f;
    bool is_running;

    is_running = false;
    f = popen(service, "r");
    if (f == NULL) {
        return false;
    }

    while (!feof(f)) {
        (void)memset(line, 0, LINE_BUF_LEN);
        if (fgets(line, LINE_BUF_LEN, f) == NULL) {
            goto out;
        }
        if (strstr(line, RUNNING) != NULL) {
            is_running = true;
            goto out;
        }
    }

out:
    (void)pclose(f);
    return is_running;
}
#endif

static bool __is_docker_running(const char *docker_command)
{
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    FILE *f;
    bool is_running;

    is_running = false;
    (void)snprintf(command, COMMAND_LEN, "%s ps 2>/dev/null", docker_command);
    f = popen(command, "r");
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

static int __get_container_count(const char *command_s)
{
    int container_num = 0;
    char line[LINE_BUF_LEN];
    char command[COMMAND_LEN];

    container_num = 0;
    command[0] = 0;
    line[0] = 0;
    (void)snprintf(command, COMMAND_LEN, "%s %s", command_s, DOCKER_COUNT_COMMAND);

    if (exec_cmd((const char *)command, line, LINE_BUF_LEN) < 0) {
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
    f = popen(command, "r");
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

        if (!exec_cmd((const char *)command, line, LINE_BUF_LEN)) {
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

    return exec_cmd((const char *)command, name, len);
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

    if (exec_cmd((const char *)command, line, LINE_BUF_LEN) < 0) {
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

    if (exec_cmd((const char *)command, pod, len) < 0) {
        return -1;
    }

    if (strstr(pod, abbr_container_id) != NULL) {
        // There is no pod
        pod[0] = 0;
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

    if (exec_cmd((const char *)command, ns, LINE_BUF_LEN) < 0) {
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

/*
parse string
[root@node2 ~]# docker inspect 92a7a60249cb | grep MergedDir | awk -F '"' '{print $4}'
                /var/lib/docker/overlay2/82c62b73874d9a17a78958d5e13af478b1185db6fa614a72e0871c1b7cd107f5/merged
*/
int get_container_merged_path(const char *abbr_container_id, char *path, unsigned int len)
{
    char command[COMMAND_LEN];

    if (!get_current_command()) {
        return -1;
    }

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    command[0] = 0;
    path[0] = 0;

    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, "%s %s", \
            CONTAINERD_MERGED_COMMAND, abbr_container_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s", \
            get_current_command(), abbr_container_id, DOCKER_MERGED_COMMAND);
    }

    return exec_cmd((const char *)command, path, len);
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

    return exec_cmd((const char *)command, buf, len);
}

/*
[root@localhost /]# docker ps -q | xargs docker inspect --format '{{.State.Pid}}, {{.Id}}' | grep -w 3013984 | awk -F ', ' '{print $2}'
f2e933da43a7e2cff0e36e1726cb91eb45a0959b02fd9b39e2dbc67022f4a88c

*/
int get_container_id_by_pid(unsigned int pid, char *container_id, unsigned int buf_len)
{
    int ret;
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];

    if (buf_len < CONTAINER_ABBR_ID_LEN + 1) {
        return -1;
    }

    if (!get_current_command()) {
        return -1;
    }

    command[0] = 0;
    line[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, CONTAINERD_ID_COMMAND, get_current_command(), get_current_command(), pid);
    } else {
        (void)snprintf(command, COMMAND_LEN, DOCKER_ID_COMMAND, get_current_command(), get_current_command(), pid);
    }

    ret = exec_cmd((const char *)command, line, LINE_BUF_LEN);
    if (ret < 0) {
        return -1;
    }

    (void)memcpy(container_id, line, CONTAINER_ABBR_ID_LEN);
    container_id[CONTAINER_ABBR_ID_LEN] = 0;
    return 0;
}

#define __PROC_CPUSET           "/proc/%s/cpuset"
#define __CAT_PROC_CPUSET_CMD   "/usr/bin/cat %s 2>/dev/null | awk -F '/' '{print $NF}'"
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
    int ret;
    char cmd[COMMAND_LEN];
    char proc_cpuset[LINE_BUF_LEN];

    if (buf_len <= CONTAINER_ABBR_ID_LEN) {
        return -1;
    }

    proc_cpuset[0] = 0;
    (void)snprintf(proc_cpuset, LINE_BUF_LEN, __PROC_CPUSET, pid);
    if (access((const char *)proc_cpuset, 0) != 0) {
        return -1;
    }

    cmd[0] = 0;
    (void)snprintf(cmd, COMMAND_LEN, __CAT_PROC_CPUSET_CMD, proc_cpuset);
    container_id[0] = 0;
    ret = exec_cmd((const char *)cmd, container_id, buf_len);
    if (ret) {
        return ret;
    }

    if (!__is_container_id(container_id)) {
        return -1;
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

    // 1. get elf_path
    (void)snprintf(cmd, COMMAND_LEN, PLDD_LIB_COMMAND, pid, comm);
    if (exec_cmd((const char *)cmd, elf_relative_path, PATH_LEN) < 0) {
        return CONTAINER_NOTOK;
    }

    // If the container id is not found, it means that gaussdb is a process on the host
    if ((get_container_id_by_pid(pid, container_id, CONTAINER_ABBR_ID_LEN + 1) >= 0) &&
        (container_id[0] != 0)) {
        if (get_container_merged_path(container_id, container_path, PATH_LEN) < 0) {
            fprintf(stderr, "get container %s merged path failed\n", container_id);
            return CONTAINER_ERR;
        }
        (void)snprintf(elf_path, max_path_len, "%s%s", container_path, elf_relative_path);
    } else {
        (void)snprintf(elf_path, max_path_len, "%s", elf_relative_path);
    }

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

    if (get_container_merged_path(container_id, container_path, PATH_LEN) < 0) {
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

#define __PID_GRP_KIND_DIR "/usr/bin/cat /proc/%u/cgroup | /usr/bin/grep -w %s | /usr/bin/awk -F ':' '{print $3}'"
#define __PID_GRP_DIR "/proc/%u/cgroup"
static int __get_cgp_dir_by_pid(unsigned int pid, const char *kind, char dir[], unsigned int dir_len)
{
    char command[COMMAND_LEN];
    char proc[PATH_LEN];

    command[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __PID_GRP_KIND_DIR, pid, kind);

    proc[0] = 0;
    (void)snprintf(proc, PATH_LEN, __PID_GRP_DIR, pid);
    if (access(proc, 0) != 0) {
        return -1;
    }

    dir[0] = 0;
    return exec_cmd((const char *)command, dir, dir_len);
}

#define __CONTAINER_GRP_KIND_DIR "/sys/fs/cgroup/%s%s"
static int __get_container_cgpdir(const char *abbr_container_id, const char *kind, char dir[], unsigned int dir_len)
{
    unsigned int pid;
    char kind_dir[PATH_LEN];

    if (__get_container_pid(abbr_container_id, &pid) < 0) {
        return -1;
    }

    kind_dir[0] = 0;
    if (__get_cgp_dir_by_pid(pid, kind, kind_dir, PATH_LEN) < 0) {
        return -1;
    }

    (void)snprintf(dir, dir_len, __CONTAINER_GRP_KIND_DIR, kind, kind_dir);
    return 0;
}


#define __STAT_INODE "/usr/bin/stat --format=%%i %s"
static int __get_fullpath_inode(const char *full_path, unsigned int *inode)
{
    char command[COMMAND_LEN];
    char inode_s[LINE_BUF_LEN];

    if (access(full_path, 0) != 0) {
        return -1;
    }

    command[0] = 0;
    inode_s[0] = 0;
    (void)snprintf(command, COMMAND_LEN, __STAT_INODE, full_path);

    if (exec_cmd((const char *)command, inode_s, LINE_BUF_LEN) < 0) {
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
    char cpucg_dir[PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    cpucg_dir[0] = 0;
    if (get_container_cpucg_dir(abbr_container_id, cpucg_dir, PATH_LEN) < 0) {
        return -1;
    }

    return __get_fullpath_inode((const char *)cpucg_dir, inode);
}

int get_container_memcg_inode(const char *abbr_container_id, unsigned int *inode)
{
    char memcg_dir[PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    memcg_dir[0] = 0;
    if (get_container_memcg_dir(abbr_container_id, memcg_dir, PATH_LEN) < 0) {
        return -1;
    }

    return __get_fullpath_inode((const char *)memcg_dir, inode);
}

int get_container_pidcg_inode(const char *abbr_container_id, unsigned int *inode)
{
    char pidcg_dir[PATH_LEN];

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    pidcg_dir[0] = 0;
    if (get_container_pidcg_dir(abbr_container_id, pidcg_dir, PATH_LEN) < 0) {
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

    int ret = exec_cmd((const char *)command, pod_id, len);
    if (ret) {
        pod_id[0] = 0;
    }

    return ret;
}

int get_pod_ip(const char *abbr_container_id, char *pod_ip_str, int len)
{
    char command[COMMAND_LEN] = {0};

    if (!get_current_command()) {
        return -1;
    }

    if (abbr_container_id == NULL || abbr_container_id[0] == 0) {
        return -1;
    }

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, CONTAINERD_IP_CMD,
            get_current_command(), abbr_container_id, get_current_command());
    } else {
        (void)snprintf(command, COMMAND_LEN, "%s inspect %s %s",
            get_current_command(), abbr_container_id, DOCKER_IP_CMD);
    }

    int ret = exec_cmd((const char *)command, pod_ip_str, len);
    if (ret) {
        pod_ip_str[0] = 0;
    }

    return ret;
}

static int __list_containers_count_by_pod_id(const char *pod_id)
{
    char command[COMMAND_LEN];
    char line[INT_LEN];

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, CONTAINERD_LIST_COUNT_COMMAND,
            get_current_command(), get_current_command(), pod_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, DOCKER_LIST_COUNT_COMMAND,
            get_current_command(), get_current_command(), pod_id);
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
    char command[COMMAND_LEN];
    char line[LINE_BUF_LEN];
    FILE *f = NULL;
    container_info *p;

    command[0] = 0;
    if (__is_containerd()) {
        (void)snprintf(command, COMMAND_LEN, CONTAINERD_LIST_CONTAINER_COMMAND,
            get_current_command(), get_current_command(), pod_id);
    } else {
        (void)snprintf(command, COMMAND_LEN, DOCKER_LIST_CONTAINER_COMMAND,
            get_current_command(), get_current_command(), pod_id);
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
    const char *fmt = "/proc/%u/ns/net";
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
    int fd = -1;
    u32 kern_version = 0;

    (void)get_kern_version(&kern_version);
    if (kern_version < KERNEL_VERSION(5, 3, 0)) {
        fd = __get_netns_fd(pid);
    } else {
        fd = __pidfd_open(pid, 0);
    }

    if (fd == -1) {
        ERROR("[TCPPROBE] Get tgid(%d)'s pidfd failed.\n", pid);
        return -1;
    }
    return setns(fd, CLONE_NEWNET);
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

