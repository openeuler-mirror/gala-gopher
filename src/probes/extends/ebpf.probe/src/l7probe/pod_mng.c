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
 * Author: wo_cow
 * Create: 2023-03-07
 * Description: eBPF prog lifecycle management
 ******************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "args.h"
#include "hash.h"
#include "container.h"
#include "include/pod.h"
#include "bpf/cgroup.skel.h"

#define POD_TBL_NAME "pod_state"
#define FAKE_POD_ID "-no-pod" // fake pod id for host container
#define KUBEPODS_PREFIX "/kubepods/"
#define DOCKER_PREFIX "/docker/"
#define PODID_PREFIX "/pod"
#define POD_ID_LEN 64
#define POD_NAME_LEN 64
#define POD_NAME_CMD "docker inspect %s --format '{{.Config.Hostname}}' 2>/dev/null"
#define POD_IP_BY_NAME_CMD "docker exec -it %s /usr/bin/cat /etc/hosts | /usr/bin/grep \"%s\" | /usr/bin/awk 'NR==1{print $1}' 2>/dev/null"
#define POD_IP_BY_END_CMD "docker exec -it %s /usr/bin/cat /etc/hosts | /usr/bin/awk 'END{print $1}' 2>/dev/null"

enum id_ret_t {
    ID_FAILED = -1,
    ID_CON_POD = 0, // pod with containers
    ID_CON_ONLY = 1, // host container
    ID_POD_ONLY = 2  // pod without containers for now
};

struct con_info_s {
    char container_name[CONTAINER_NAME_LEN];
    char libc_path[PATH_LEN];
    char libssl_path[PATH_LEN];
};

struct containers_hash_t {
    H_HANDLE;
    char con_id[CONTAINER_ABBR_ID_LEN]; // key
    struct con_info_s con_info; // value
};

struct pod_info_s {
    char pod_name[POD_NAME_LEN];
    char pod_ip_str[INET6_ADDRSTRLEN];
    struct containers_hash_t *con_head;
};

struct pods_hash_t {
    H_HANDLE;
    char pod_id[POD_ID_LEN]; // key
    struct pod_info_s pod_info; // value
};

static struct pods_hash_t *pod_head = NULL;

static void print_pod_state_metrics(struct pod_info_s *pod_info, struct containers_hash_t *con, const char *event)
{
    fprintf(stdout,
            "|%s|%s|%s|%s|%s|%s|%d|\n",
            POD_TBL_NAME,
            pod_info->pod_name,
            event,
            pod_info->pod_ip_str,
            con->con_id,
            con->con_info.container_name,
            0);

    (void)fflush(stdout);
}

static void get_pod_name(char *con_id, char *pod_name, int len)
{
    char command[COMMAND_LEN] = {0};

    (void)snprintf(command, COMMAND_LEN, POD_NAME_CMD, con_id);

    if (exec_cmd((const char *)command, pod_name, len)) {
        pod_name[0] = 0;
    }
}

static void get_pod_ip(char *con_id, char *pod_name, char *pod_ip_str, int len)
{
    char command[COMMAND_LEN] = {0};

    if (pod_name[0] != 0) {
        (void)snprintf(command, COMMAND_LEN, POD_IP_BY_NAME_CMD, con_id, pod_name);
    } else {
        (void)snprintf(command, COMMAND_LEN, POD_IP_BY_END_CMD, con_id);
    }

    if (exec_cmd((const char *)command, pod_ip_str, len)) {
        pod_ip_str[0] = 0;
    }
}

static enum id_ret_t get_pod_container_id(char *cgrp_path, char *pod_id, char *con_id)
{
    int full_path_len;
    char *p;
    int i,j;
    int ret;
    if (!cgrp_path) {
        return ID_FAILED;
    }

    full_path_len = strlen(cgrp_path);

    if (strstr(cgrp_path, KUBEPODS_PREFIX) != NULL) {
        p = strstr(cgrp_path, PODID_PREFIX);
        if (p == NULL) {
            return ID_FAILED;
        }
        // get pod id
        p += 4;
        i = 0;
        while (i < POD_ID_LEN && i + p - cgrp_path < full_path_len) {
            if (p[i] == '/') {
                pod_id[i++] = 0;
                break;
            }
            pod_id[i] = p[i];
            i++;
        }
        pod_id[POD_ID_LEN - 1] = 0;
        if (i + p - cgrp_path == full_path_len) {
            return ID_POD_ONLY;
        }
        ret = ID_CON_POD;
    } else if ((p = strstr(cgrp_path, DOCKER_PREFIX)) != NULL) {
        // set fake pod id
        i = 8;
        (void)strncpy(pod_id, FAKE_POD_ID, POD_ID_LEN - 1);
        ret = ID_CON_ONLY;
    } else {
        return ID_FAILED;
    }

    // get container id
    p += i;
    j = 0;
    while (j < CONTAINER_ABBR_ID_LEN && j + p - cgrp_path < full_path_len) {
        if (p[j] == '/') {
            con_id[j++] = 0;
            break;
        }
        con_id[j] = p[j];
        j++;
    }
    con_id[CONTAINER_ABBR_ID_LEN - 1] = 0;
    return ret;
}

static int add_con_hash(struct containers_hash_t **con_head, char *con_id)
{
    struct containers_hash_t *new_container = malloc(sizeof(struct containers_hash_t));
    if (new_container == NULL) {
        return -1;
    }

    (void)memset(new_container, 0, sizeof(struct containers_hash_t));
    (void)strncpy(new_container->con_id, con_id, CONTAINER_ABBR_ID_LEN - 1);
    H_ADD_S(*con_head, con_id, new_container);

    return 0;
}

static struct containers_hash_t *add_one_con(struct pod_info_s *pod_info, char *con_id)
{
    struct containers_hash_t *con = NULL;
    int ret;

    if (con_id == NULL || con_id[0] == 0) {
        ERROR("[L7PROBE]: Failed to add one container. container id is null\n");
        return NULL;
    }

    if (add_con_hash(&pod_info->con_head, con_id) != 0) {
        ERROR("[L7PROBE]: Failed to malloc container %s hash.\n", con_id);
        return NULL;
    }

    H_FIND_S(pod_info->con_head, con_id, con);
    if (con == NULL) {
        ERROR("[L7PROBE]: Failed to add container %s hash.\n", con_id);
        return NULL;
    }

    ret = get_container_name(con_id, con->con_info.container_name, CONTAINER_NAME_LEN);
    if (ret) {
        ERROR("[L7PROBE]: Failed to get container name of container %s.\n", con_id);
    }

    get_elf_path_by_con_id(con_id, con->con_info.libc_path, PATH_LEN, "libc.so");
    get_elf_path_by_con_id(con_id, con->con_info.libssl_path, PATH_LEN, "libssl");
    print_pod_state_metrics(pod_info, con, "create_container");

    return con;
}

static void del_one_con(struct pod_info_s *pod_info, char *con_id)
{
    struct containers_hash_t *con_head = pod_info->con_head;
    struct containers_hash_t *con;

    if (con_head == NULL) {
        return;
    }

    H_FIND_S(con_head, con_id, con);
    if (con != NULL) {
        print_pod_state_metrics(pod_info, con, "destroy_container");
        H_DEL(con_head, con);
        (void)free(con);
    }
}

static void del_cons(struct containers_hash_t **con_head)
{
    struct containers_hash_t *con, *tmp;
    if (*con_head == NULL) {
        return;
    }
    
    if (H_COUNT(*con_head) > 0) {
        H_ITER(*con_head, con, tmp) {
            H_DEL(*con_head, con);
            (void)free(con);
        }
    }

    *con_head = NULL;
}

static int add_pod_hash(char *pod_id)
{
    struct pods_hash_t *new_pod = malloc(sizeof(struct pods_hash_t));
    if (new_pod == NULL) {
        return -1;
    }

    (void)memset(new_pod, 0, sizeof(struct pods_hash_t));
    (void)strncpy(new_pod->pod_id, pod_id, POD_ID_LEN - 1);
    H_ADD_S(pod_head, pod_id, new_pod);

    return 0;
}

static struct pods_hash_t *add_one_pod(char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    struct pods_hash_t *pod = NULL;

    if (pod_id == NULL || pod_id[0] == 0) {
        ERROR("[L7PROBE]: Failed to add one pod. pod id is null\n");
        return NULL;
    }

    H_FIND_S(pod_head, pod_id, pod);
    if (pod == NULL) {
        if (add_pod_hash(pod_id) != 0) {
            ERROR("[L7PROBE]: Failed to malloc pod %s hash.\n", pod_id);
            return NULL;
        }

        H_FIND_S(pod_head, pod_id, pod);
        if (pod == NULL) {
            ERROR("[L7PROBE]: Failed to add pod %s hash.\n", pod_id);
            return NULL;
        }
    }

    if (con_id[0] != 0 && id_ret != ID_CON_ONLY) {
        if (pod->pod_info.pod_name[0] == 0) {
            get_pod_name(con_id, pod->pod_info.pod_name, POD_NAME_LEN);
        }
        if (pod->pod_info.pod_ip_str[0] == 0) {
            get_pod_ip(con_id, pod->pod_info.pod_name, pod->pod_info.pod_ip_str, INET6_ADDRSTRLEN);
        }
    }

    return pod;
}

static void del_one_pod(char *pod_id)
{
    struct pods_hash_t *pod = NULL;

    H_FIND_S(pod_head, pod_id, pod);
    if (pod == NULL) {
        return;
    }

    if (pod->pod_info.con_head != NULL) {
        del_cons(&pod->pod_info.con_head);
    }

    H_DEL(pod_head, pod);
    (void)free(pod);
}

void del_pods()
{
    struct pods_hash_t *pod, *tmp;

    if (pod_head == NULL) {
        return;
    }

    H_ITER(pod_head, pod, tmp) {
        if (pod->pod_info.con_head != NULL) {
            del_cons(&pod->pod_info.con_head);
        }
        H_DEL(pod_head, pod);
        (void)free(pod);
    }

    pod_head = NULL;
}

static void cgrp_mk_process(char *cgrp_path)
{
    char pod_id[POD_ID_LEN] = {0};
    char con_id[CONTAINER_ABBR_ID_LEN] = {0};
    struct pods_hash_t *pod = NULL;
    enum id_ret_t id_ret = 0;

    id_ret = get_pod_container_id(cgrp_path, pod_id, con_id);

    if (id_ret == ID_FAILED) {
        return;
    }

    pod = add_one_pod(pod_id, con_id, id_ret);
    if (pod == NULL) {
        return;
    }

    if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
        add_one_con(&pod->pod_info, con_id);
    }

    return;
}

static void cgrp_rm_process(char *cgrp_path)
{
    char pod_id[POD_ID_LEN] = {0};
    char con_id[CONTAINER_ABBR_ID_LEN] = {0};
    struct pods_hash_t *pod = NULL;
    enum id_ret_t id_ret = 0;

    id_ret = get_pod_container_id(cgrp_path, pod_id, con_id);
    
    if (id_ret == ID_FAILED) {
        return;
    }
    
    if (id_ret == ID_POD_ONLY) {
        del_one_pod(pod_id);
    } else if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
        H_FIND_S(pod_head, pod_id, pod);
        if (pod != NULL) {
            del_one_con(&pod->pod_info, con_id);
            return;
        }
    }
}

void l7_cgroup_msg_handler(void *ctx, int cpu, void *data, unsigned int size)
{
    struct cgroup_msg_data_t *msg_data = (struct cgroup_msg_data_t *)data;

    if (msg_data->cgrp_event == CGRP_MK) {
        cgrp_mk_process(msg_data->cgrp_path);
    } else {
        cgrp_rm_process(msg_data->cgrp_path);
    }

    return;
}
