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
#include "object.h"
#include "ipc.h"
#include "container.h"
#include "pod_mng.h"

#define POD_TBL_NAME "pod_state"
#define KUBEPODS_PREFIX "/kubepods/"
#define DOCKER_PREFIX "/docker/"
#define PODID_PREFIX "/pod"

#define FILTER_FLAGS_IGNORE 0x0000  // default value
#define FILTER_FLAGS_NORMAL 0x0001

struct pods_hash_t {
    H_HANDLE;
    char pod_id[POD_ID_LEN + 1]; // key
    struct pod_info_s pod_info; // value
};

static struct pods_hash_t *pod_head = NULL;

#if 0
static void print_pod_state_metrics(struct pod_info_s *pod_info, struct containers_hash_t *con, const char *event)
{
    fprintf(stdout,
            "|%s|%s|%s|%s|%s|%d|\n",
            POD_TBL_NAME,
            event,
            pod_info->pod_ip_str,
            con->con_id,
            con->con_info.container_name,
            0);

    (void)fflush(stdout);
}
#endif

enum id_ret_t get_pod_container_id(char *cgrp_path, char *pod_id, char *con_id)
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
        /* In the k8s scenario, cgrp_path is like:
         * /kubepods/besteffort/pod6cfd4235-599f-493a-9880-970f3a3d4c31/50a3732f21659025473ae82f575cdac290e945d3191ae9286fd27dc36da0aa44
         * /kubepods/besteffort/pod<pod_id>/<con_id>
         */
        p = strstr(cgrp_path, PODID_PREFIX);
        if (p == NULL) {
            return ID_FAILED;
        }
        // get pod id
        p += 4; // "/pod"
        i = 0;
        while (i < POD_ID_LEN && i + p - cgrp_path < full_path_len) {
            if (p[i] == '/') {
                pod_id[i++] = 0;
                break;
            }
            pod_id[i] = p[i];
            i++;
        }
        pod_id[POD_ID_LEN] = 0;
        if (i + p - cgrp_path == full_path_len) {
            return ID_POD_ONLY;
        }
        ret = ID_CON_POD;
    } else if ((p = strstr(cgrp_path, DOCKER_PREFIX)) != NULL) {
        /* In the docker scenario, cgrp_path is like:
         * /docker/a5034afbb059c76c0f4a6ff44ff9a524770744695b6b320d52a08e4c020e37c2
         * /docker/<con_id>
         */
        // set fake pod id

        i = 8; // "/docker/"
        (void)snprintf(pod_id, POD_ID_LEN + 1, "%s", FAKE_POD_ID);
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
    con_id[CONTAINER_ABBR_ID_LEN] = 0;
    return ret;
}

struct con_info_s *get_con_info(char *pod_id, char *con_id)
{
    struct containers_hash_t *con = NULL;
    struct pod_info_s *pod_info = get_pod_info_from_pod_id(pod_id);
    if (pod_info == NULL) {
        return NULL;
    }

    H_FIND_S(pod_info->con_head, con_id, con);
    if (con == NULL) {
        return NULL;
    }

    return &con->con_info;
}

static int add_con_hash(struct containers_hash_t **con_head, char *con_id)
{
    struct containers_hash_t *new_container = malloc(sizeof(struct containers_hash_t));
    if (new_container == NULL) {
        return -1;
    }

    (void)memset(new_container, 0, sizeof(struct containers_hash_t));
    (void)strncpy(new_container->con_id, con_id, CONTAINER_ABBR_ID_LEN);
    H_ADD_S(*con_head, con_id, new_container);

    return 0;
}

static void set_con_info(struct pod_info_s *pod_info, char *con_id,  struct containers_hash_t *con)
{
    con->con_info.pod_info_ptr = pod_info;

    if (con->con_info.con_id[0] == 0) {
        (void)snprintf(con->con_info.con_id, sizeof(con->con_info.con_id), "%s", con_id);
    }

    int ret = get_container_cpucg_inode((const char *)con_id, &con->con_info.cpucg_inode);
    if (ret) {
        ERROR("Failed to get cpucg inode of container %s.\n", con_id);
    }

    ret = get_container_name(con_id, con->con_info.container_name, CONTAINER_NAME_LEN);
    if (ret) {
        ERROR("Failed to get container name of container %s.\n", con_id);
    }

    get_elf_path_by_con_id(con_id, con->con_info.libc_path, PATH_LEN, "libc");
    get_elf_path_by_con_id(con_id, con->con_info.libssl_path, PATH_LEN, "libssl");

    return;
}

static struct containers_hash_t *add_one_con(struct pod_info_s *pod_info, char *con_id)
{
    struct containers_hash_t *con = NULL;
    int ret;

    if (con_id == NULL || con_id[0] == 0) {
        ERROR("Failed to add one container. container id is null\n");
        return NULL;
    }

    if (add_con_hash(&pod_info->con_head, con_id) != 0) {
        ERROR("Failed to malloc container %s hash.\n", con_id);
        return NULL;
    }

    H_FIND_S(pod_info->con_head, con_id, con);
    if (con == NULL) {
        ERROR("Failed to add container %s hash.\n", con_id);
        return NULL;
    }

    set_con_info(pod_info, con_id, con);
    // print_pod_state_metrics(pod_info, con, "create_container");

    return con;
}

static void del_one_con(struct pod_info_s *pod_info, char *con_id)
{
    struct containers_hash_t *con;

    if (pod_info->con_head == NULL) {
        return;
    }

    H_FIND_S(pod_info->con_head, con_id, con);
    if (con != NULL) {
        //print_pod_state_metrics(pod_info, con, "destroy_container");
        H_DEL(pod_info->con_head, con);
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

struct pod_info_s *get_pod_info_from_pod_id(char *pod_id)
{
    struct pods_hash_t *pod = NULL;
    if (pod_id == NULL || pod_id[0] == 0) {
        return NULL;
    }
    H_FIND_S(pod_head, pod_id, pod);
    if (pod != NULL) {
        return &pod->pod_info;
    }
    return NULL;
}

static int add_pod_hash(char *pod_id)
{
    struct pods_hash_t *new_pod = malloc(sizeof(struct pods_hash_t));
    if (new_pod == NULL) {
        return -1;
    }

    (void)memset(new_pod, 0, sizeof(struct pods_hash_t));
    (void)strncpy(new_pod->pod_id, pod_id, POD_ID_LEN);
    H_ADD_S(pod_head, pod_id, new_pod);

    return 0;
}

static void set_pod_info(char *pod_id, char *con_id, struct pods_hash_t *pod)
{
    if (pod->pod_info.pod_id[0] == 0) {
        (void)snprintf(pod->pod_info.pod_id, sizeof(pod->pod_info.pod_id), "%s", pod_id);
    }
    if (pod->pod_info.pod_ip_str[0] == 0) {
        (void)get_pod_ip((const char *)con_id, pod->pod_info.pod_ip_str, INET6_ADDRSTRLEN);
    }

    return;
}

static struct pods_hash_t *add_one_pod(char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    struct pods_hash_t *pod = NULL;

    if (pod_id == NULL || pod_id[0] == 0) {
        ERROR("Failed to add one pod. pod id is null\n");
        return NULL;
    }

    H_FIND_S(pod_head, pod_id, pod);
    if (pod == NULL) {
        if (add_pod_hash(pod_id) != 0) {
            ERROR("Failed to malloc pod %s hash.\n", pod_id);
            return NULL;
        }

        H_FIND_S(pod_head, pod_id, pod);
        if (pod == NULL) {
            ERROR("Failed to add pod %s hash.\n", pod_id);
            return NULL;
        }
    }

    if (con_id[0] != 0 && id_ret != ID_CON_ONLY) {
        set_pod_info(pod_id, con_id, pod);
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

// Add the existed pods before the program starts to the map
void existing_pod_mk_process(char *pod_id)
{
    container_info *cs = NULL;
    container_tbl* cstbl = list_containers_by_pod_id((const char *)pod_id);
    if (cstbl == NULL) {
        return;
    }

    for (int i = 0; i < cstbl->num; i++) {
        cs = cstbl->cs + i;
        add_pod_con_map(pod_id, cs->abbrContainerId, ID_CON_POD);
    }

    free_container_tbl(&cstbl);
    return;
}

void add_pod_con_map(char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    struct pods_hash_t *pod = add_one_pod(pod_id, con_id, id_ret);
    if (pod == NULL) {
        return;
    }

    if (id_ret == ID_CON_POD || id_ret == ID_CON_ONLY) {
        add_one_con(&pod->pod_info, con_id);
    }

    return;
}

void del_pod_con_map(char *pod_id, char *con_id, enum id_ret_t id_ret)
{
    struct pods_hash_t *pod = NULL;

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

// Try to get con_info. If can't then try to add.
struct con_info_s *get_and_add_con_info(char *pod_id, char *container_id)
{
    if (container_id == NULL) {
        return NULL;
    }

    char con_id[CONTAINER_ABBR_ID_LEN + 1];
    con_id[0] = 0;
    (void)snprintf(con_id, sizeof(con_id), "%s", container_id);

    struct con_info_s *con_info = get_con_info(pod_id, con_id);
    if (con_info != NULL) {
        return con_info;
    }

    // add_con_info
    add_pod_con_map(pod_id, con_id, ID_CON_ONLY);

    return get_con_info(pod_id, con_id);
}

// Try to get pod_info. If can't then try to add.
struct pod_info_s *get_and_add_pod_info(char *pod_id)
{
    if (pod_id == NULL) {
        return NULL;
    }

    struct pod_info_s *pod_info = get_pod_info_from_pod_id(pod_id);
    if (pod_info != NULL) {
        return pod_info;
    }

    // add_pod_info
    existing_pod_mk_process(pod_id);
    return get_pod_info_from_pod_id(pod_id);
}

typedef enum cb_rslt_t {
    CB_CONTINUE,
    CB_STOP,
    CB_ERR
} cb_rslt;

typedef struct cb_params_s {
    int flags;
    int result;
} cb_params;

static int is_update_container_filter(struct containers_hash_t *con, enum filter_op_t op)
{
    if ((con->con_info.flags & FILTER_FLAGS_IGNORE) && (op == FILTER_OP_ADD)) {
        return 1;
    }

    if ((con->con_info.flags & FILTER_FLAGS_NORMAL) && (op == FILTER_OP_RM)) {
        return 1;
    }
    return 0;
}

static void update_container_filter(struct containers_hash_t *con, enum filter_op_t op)
{
    switch (op) {
        case FILTER_OP_ADD:
            con->con_info.flags = FILTER_FLAGS_NORMAL;
            break;
        case FILTER_OP_RM:
            con->con_info.flags = FILTER_FLAGS_IGNORE;
            break;
    }
}

typedef cb_rslt (*callback_container_func)(struct containers_hash_t *, cb_params *);
static cb_rslt container_filter_op(struct containers_hash_t *con, cb_params *params)
{
    int ret;
    unsigned int cpuacct_inode;
    enum filter_op_t op = (enum filter_op_t)(params->flags);

    if (!is_update_container_filter(con, op)) {
        params->result = 0;
        ret = 0;
        goto end;
    }

    ret = get_container_cpucg_inode((const char *)(con->con_id), &cpuacct_inode);
    if (ret != 0) {
        goto end;
    }

    struct cgroup_s cpuacct_obj = {.knid = cpuacct_inode, .type = CGP_TYPE_CPUACCT};
    switch (op) {
        case FILTER_OP_ADD:
            ret = cgrp_add(&cpuacct_obj);
            break;
        case FILTER_OP_RM:
            ret = cgrp_put(&cpuacct_obj);
            break;
    }

    if (ret < 0) {
        ERROR("Failed to op container filter[op_code = %d, id = %s] .\n", params->flags, con->con_id);
    }
    params->result = ret;
    update_container_filter(con, op);

end:
    return (ret < 0) ? CB_ERR : CB_CONTINUE;
}

static cb_rslt single_container_filter_op(struct containers_hash_t *con, cb_params *params)
{
    int ret;
    unsigned int cpuacct_inode;
    enum filter_op_t op = (enum filter_op_t)(params->flags);

    if (!is_update_container_filter(con, op)) {
        params->result = 0;
        ret = 0;
        goto end;
    }

    ret = get_container_cpucg_inode((const char *)(con->con_id), &cpuacct_inode);
    if (ret != 0) {
        goto end;
    }

    struct cgroup_s cpuacct_obj = {.knid = cpuacct_inode, .type = CGP_TYPE_CPUACCT};
    switch (op) {
        case FILTER_OP_ADD:
            ret = cgrp_add(&cpuacct_obj);
            break;
        case FILTER_OP_RM:
            ret = cgrp_put(&cpuacct_obj);
            break;
    }

    if (ret < 0) {
        ERROR("Failed to op container filter[op_code = %d, id = %s] .\n", params->flags, con->con_id);
    }
    params->result = ret;
    update_container_filter(con, op);

end:
    return (ret < 0) ? CB_ERR : CB_STOP;
}

static cb_rslt walk_container_tbl(const char *container_id, struct containers_hash_t *con_head,
                                            callback_container_func cb, cb_params *params)
{
    cb_rslt rslt = CB_CONTINUE;
    struct containers_hash_t *con, *tmp;
    if (con_head == NULL) {
        goto end;
    }

    H_ITER(con_head, con, tmp) {
        if ((container_id != NULL) && (strcmp((const char*)con->con_id, container_id) == 0)) {
            rslt = cb(con, params);
            goto end; // Should stop walker for indicates the container ID.
        } else if (container_id == NULL) {
            rslt = cb(con, params);
        }
        if (rslt != CB_CONTINUE) {
            break;
        }
    }
end:
    return rslt;
}

static cb_rslt walk_pod_tbl(const char *pod_id, const char *container_id, callback_container_func cb, cb_params *params)
{
    cb_rslt rslt = CB_CONTINUE;
    struct pods_hash_t *pod, *tmp;

    H_ITER(pod_head, pod, tmp) {
        if ((pod_id != NULL) && (strcmp((const char*)pod->pod_id, pod_id) == 0)) {
            rslt = walk_container_tbl(container_id, pod->pod_info.con_head, cb, params);
            goto end; // Should stop walker for indicates the pod ID.
        } else if (pod_id == NULL) {
            rslt = walk_container_tbl(container_id, pod->pod_info.con_head, cb, params);
        }
        if (rslt != CB_CONTINUE) {
            break;
        }
    }
end:
    return rslt;
}

int filter_pod_op(const char *pod_id, enum filter_op_t op)
{
    cb_params params = {.flags = (int)op, .result = -1};
    cb_rslt rslt = walk_pod_tbl(pod_id, NULL, container_filter_op, &params);
    return rslt;
}

int filter_container_op(const char *container_id, enum filter_op_t op)
{
    cb_params params = {.flags = (int)op, .result = -1};
    cb_rslt rslt = walk_pod_tbl(NULL, container_id, single_container_filter_op, &params);
    return rslt;
}

void free_con_id_list(con_id_element *con_id_list)
{
    con_id_element *con_info_elem, *tmp;

    if (con_id_list == NULL) {
        return;
    }

    LL_FOREACH_SAFE(con_id_list, con_info_elem, tmp) {
        LL_DELETE(con_id_list, con_info_elem);
        free(con_info_elem);
    }
}

int append_con_id_list(con_id_element **con_id_list, struct con_info_s *con_info)
{
    con_id_element *con_info_elem, *tmp;

    con_info_elem = (con_id_element *)malloc(sizeof(con_id_element));
    if (con_info_elem == NULL) {
        return -1;
    }

    con_info_elem->con_id = con_info->con_id;
    LL_APPEND(*con_id_list, con_info_elem);
    return 0;
}

