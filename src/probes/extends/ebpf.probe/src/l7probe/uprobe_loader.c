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
 * Create: 2023-03-15
 * Description: Dynamic loading and unloading uprobe
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "bpf.h"
#include "elf_reader.h"
#include "container.h"
#include "include/uprobe_loader.h"

extern volatile sig_atomic_t stop; // readonly here

static void __set_pids_inactive(struct proc_bpf_hash_t **head)
{
    struct proc_bpf_hash_t *item, *tmp;
    if (*head == NULL) {
        return;
    }
    
    H_ITER(*head, item, tmp) {
        item->v.pid_state = PID_NOEXIST;
    }
}

static int __add_bpf_link(int pidd, struct proc_bpf_hash_t **head, const char *libname)
{
    struct proc_bpf_hash_t *item = malloc(sizeof(struct proc_bpf_hash_t));
    if (item == NULL) {
        fprintf(stderr, "malloc bpf link %u failed\n", pidd);
        return -1;
    }
    (void)memset(item, 0, sizeof(struct proc_bpf_hash_t));
    if (get_elf_path(pidd, item->v.elf_path, MAX_PATH_LEN, libname) != CONTAINER_OK) {
        free(item);
        return -1;
    }

    item->pid = pidd;
    item->v.pid_state = PID_ELF_TOBE_ATTACHED;
    H_ADD(*head, pid, sizeof(int), item);
    return 0;
}

static struct proc_bpf_hash_t* __find_bpf_link(int pid, struct proc_bpf_hash_t **head)
{
    struct proc_bpf_hash_t *item = NULL;

    if (*head == NULL) {
        return NULL;
    }
    H_FIND(*head, &pid, sizeof(int), item);
    if (item == NULL) {
        return NULL;
    }

    if (item->v.bpf_links[0] == NULL) {
        item->v.pid_state = PID_ELF_NO_NEED_ATTACHED;
    } else {
        item->v.pid_state = PID_ELF_ATTACHED;
    }

    return item;
}

static void __add_pids(int proc_obj_map_fd, struct proc_bpf_hash_t **head, const char *libname)
{
    int pid = 0;
    int ret = 0;
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s value = {0};

    while (bpf_map_get_next_key(proc_obj_map_fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(proc_obj_map_fd, &next_key, &value);
        key = next_key;
        if (ret < 0) {
            continue;
        }

        pid = key.proc_id;
        // find_bpf_link and add_bpf_link will set bpf_link status
        if (!__find_bpf_link(pid, head)) {
            if (__add_bpf_link(pid, head, libname) == 0) {
                INFO("Add of pid %u success\n", pid);
            }
        }
    }

    return;
}

static void __clear_invalid_pids(struct proc_bpf_hash_t **head)
{
    struct proc_bpf_hash_t *pid_bpf_links, *tmp;
    if (*head == NULL) {
        return;
    }
    H_ITER(*head, pid_bpf_links, tmp) {
        if (pid_bpf_links->v.pid_state == PID_NOEXIST) {
            INFO("Clear bpf link of pid %u\n", pid_bpf_links->pid);
            H_DEL(*head, pid_bpf_links);
            (void)free(pid_bpf_links);
        }
    }
}

static bool __get_bpf_prog(struct bpf_program *prog, char func_sec[], int func_len)
{
    const char *bpfpg_name = bpf_program__name(prog);
    memset(func_sec, 0, func_len);
    bool is_uretprobe = strstr(bpfpg_name, "ubpf_ret_") ? true : false;
    if (is_uretprobe) {
        (void)strcpy(func_sec, bpfpg_name + 9); // ubpf_ret_
    } else {
        (void)strcpy(func_sec, bpfpg_name + 5);  // ubpf_
    }

    
    return is_uretprobe;
}

static void __unload_bpf_progs(struct proc_bpf_hash_t **head)
{
    struct proc_bpf_hash_t *pid_bpf_links, *tmp;
    if (*head == NULL) {
        return;
    }

    H_ITER(*head, pid_bpf_links, tmp) {
        if (pid_bpf_links->v.pid_state == PID_ELF_ATTACHED) {
            for (int i = 0; i < pid_bpf_links->v.bpf_link_num; i++) {
                bpf_link__destroy(pid_bpf_links->v.bpf_links[i]);
            }
            H_DEL(*head, pid_bpf_links);
            (void)free(pid_bpf_links);
            INFO("Detach memleak bpf to pid %u success\n", pid_bpf_links->pid);
        }
    }
}

static void __close_bpf_obj(struct bpf_object *obj)
{
    if (obj) {
        bpf_object__close(obj);
    }
}
#define BPF_FUNC_NAME_LEN 32
static void __attach_bpf_progs_in_proc(struct bpf_object *obj, struct proc_bpf_hash_t *pid_bpf_links, int *init)
{
    struct bpf_program *prog;
    char func_sec[BPF_FUNC_NAME_LEN] = {0};
    bool is_uretprobe;
    const char *elf_path;
    u64 symbol_offset;
    int err;
    int i = 0;

    bpf_object__for_each_program(prog, obj) { // for bpf progs
        is_uretprobe = __get_bpf_prog(prog, func_sec, BPF_FUNC_NAME_LEN);
        elf_path = (const char *)pid_bpf_links->v.elf_path;
        err = gopher_get_elf_symb(elf_path, func_sec, &symbol_offset);
        if (err < 0) {
            ERROR("Failed to get func(%s) in(%s) offset.\n", func_sec, elf_path);
            break;
        }
        pid_bpf_links->v.bpf_links[i] = bpf_program__attach_uprobe(prog, is_uretprobe, -1,
            elf_path, (size_t)symbol_offset);
        err = libbpf_get_error(pid_bpf_links->v.bpf_links[i]); 
        if (err) {
            ERROR("Attach bpf to pid %u failed %d\n", pid_bpf_links->pid, err);
            break;
        }
        if (*init == 0) {
            *init = 1;
        }
        i++;
    }
    if (err == 0) {
        pid_bpf_links->v.pid_state = PID_ELF_ATTACHED;
        pid_bpf_links->v.bpf_link_num = i;
        INFO("Attach bpf to pid %u success\n", pid_bpf_links->pid);
    } else {
        pid_bpf_links->v.bpf_links[i] = NULL;
        for (i--; i >= 0; i--) {
            bpf_link__destroy(pid_bpf_links->v.bpf_links[i]);
        }
    }

    return;
}

#define DEFAULT_LOAD_PERIOD 5
void *load_n_unload_uprobe(void *arg)
{
    struct proc_load_args_s *args = (struct proc_load_args_s *)arg;
    struct proc_bpf_hash_t *pid_bpf_links, *tmp;
    struct proc_bpf_hash_t *head = NULL;
    struct bpf_object *obj = args->bpf_obj;
    int *init = args->init;
    while (!stop) {
        __set_pids_inactive(&head);
        __add_pids(args->proc_obj_map_fd, &head, args->libname);
        H_ITER(head, pid_bpf_links, tmp) { // for pids
            if (pid_bpf_links->v.pid_state == PID_ELF_TOBE_ATTACHED) {
                __attach_bpf_progs_in_proc(obj, pid_bpf_links, init);
            }
        }
        __clear_invalid_pids(&head);
        sleep(DEFAULT_LOAD_PERIOD);
    }
    // TODO: check if clean
    __unload_bpf_progs(&head);
    __close_bpf_obj(obj);
    return NULL;
}
