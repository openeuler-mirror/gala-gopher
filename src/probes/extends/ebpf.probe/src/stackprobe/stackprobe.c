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
 * Author: luzhihao
 * Create: 2022-08-22
 * Description: stack probe user prog
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

#include <linux/perf_event.h>
#include <linux/unistd.h>

#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#include "bpf.h"
#include "ipc.h"
#include "hash.h"
#include "logs.h"
#include "syscall.h"
#include "symbol.h"
#include "flame_graph.h"
#include "debug_elf_reader.h"
#include "elf_symb.h"
#include "container.h"
#include "stackprobe.h"
#include "java_support.h"

#define IS_LOAD_PROBE(LOAD_TYPE, PROG_TYPE) (LOAD_TYPE & PROG_TYPE)

#define ON_CPU_PROG    "/opt/gala-gopher/extend_probes/stack_bpf/oncpu.bpf.o"
#define OFF_CPU_PROG   "/opt/gala-gopher/extend_probes/stack_bpf/offcpu.bpf.o"
#define IO_PROG        "/opt/gala-gopher/extend_probes/stack_bpf/io.bpf.o"
#if defined(__TARGET_ARCH_x86)
#define MEM_PROG   "/opt/gala-gopher/extend_probes/stack_bpf/mem.bpf.o"
#else
#define MEM_PROG   "/opt/gala-gopher/extend_probes/stack_bpf/mem_fp.bpf.o"
#endif
#define RM_STACK_PATH "/usr/bin/rm -rf /sys/fs/bpf/gala-gopher/__stack*"
#define STACK_PROC_MAP_PATH     "/sys/fs/bpf/gala-gopher/__stack_proc_map"
#define STACK_CONVERT_PATH      "/sys/fs/bpf/gala-gopher/__stack_convert"
#define STACK_STACKMAPA_PATH    "/sys/fs/bpf/gala-gopher/__stack_stackmap_a"
#define STACK_STACKMAPB_PATH    "/sys/fs/bpf/gala-gopher/__stack_stackmap_b"

#define DEBUG_DIR "/usr/lib/debug"

#define IS_IEG_ADDR(addr)     ((addr) != 0xcccccccccccccccc && (addr) != 0xffffffffffffffff)

#define MEM_SEC_NUM 4
#define HISTO_TMP_LEN   (2 * STACK_SYMBS_LEN)
#define POST_MAX_STEP_SIZE 1048576 // 1M

typedef int (*AttachFunc)(struct ipc_body_s *ipc_body, struct svg_stack_trace_s *svg_st);
typedef int (*PerfProcessFunc)(void *ctx, int cpu, void *data, u32 size);

struct proc_histo_tmp_s {
    enum stack_svg_type_e en_type;
    int load_symbs;
    struct proc_symbs_s *proc_symbs;
    struct proc_stack_trace_histo_s *proc_histo;
};

typedef struct {
    u32 sw;
    enum stack_svg_type_e en_type;
    char *flame_name;
    char *prog_name;
    AttachFunc func;
    perf_buffer_sample_fn cb;
} FlameProc;
#if 0
static struct bpf_link_hash_t *bpf_link_head = NULL;

enum pid_state_t {
    PID_NOEXIST,
    PID_ELF_TOBE_ATTACHED,
    PID_ELF_ATTACHED
};
struct bpf_link_hash_value {
    enum pid_state_t pid_state;
    char elf_path[MAX_PATH_LEN];
    int bpf_link_num;
    struct bpf_link *bpf_links[32]; // 32 cover num of probes in mem.bpf.c
};

struct bpf_link_hash_t {
    H_HANDLE;
    unsigned int pid; // key
    struct bpf_link_hash_value v; // value
};
#endif

static char __histo_tmp_str[HISTO_TMP_LEN];
int g_post_max = POST_MAX_STEP_SIZE;
static struct ipc_body_s g_ipc_body;
static volatile sig_atomic_t g_stop;
static struct stack_trace_s *g_st = NULL;

static void sig_int(int signo)
{
    g_stop = 1;
}

static void load_stackprobe_snoopers(struct ipc_body_s *ipc_body)
{
    struct proc_s proc = {0};
    struct obj_ref_s ref = {.count = 1};
    if (!g_st || (g_st->proc_obj_map_fd <= 0)) {
        ERROR("[STACKPROBE]: Load stackprobe snoopers failed!\n");
        return;
    }

    for (int i = 0; i < ipc_body->snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (ipc_body->snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            proc.proc_id = ipc_body->snooper_objs[i].obj.proc.proc_id;
            (void)bpf_map_update_elem(g_st->proc_obj_map_fd, &proc, &ref, BPF_ANY);
        }
    }
}

static void unload_stackprobe_snoopers()
{
    struct proc_s proc = {0};
    if (!g_st || (g_st->proc_obj_map_fd <= 0)) {
        return;
    }

    for (int i = 0; i < g_ipc_body.snooper_obj_num && i < SNOOPER_MAX; i++) {
        if (g_ipc_body.snooper_objs[i].type == SNOOPER_OBJ_PROC) {
            proc.proc_id = g_ipc_body.snooper_objs[i].obj.proc.proc_id;
            (void)bpf_map_delete_elem(g_st->proc_obj_map_fd, &proc);
        }
    }
}

#if 1

int stacktrace_create_log_mgr(struct stack_trace_s *st, const char *logDir)
{
    struct log_mgr_s* mgr = create_log_mgr(NULL, 0, 0);
    if (!mgr) {
        return -1;
    }

    (void)snprintf(mgr->debug_path, sizeof(mgr->debug_path), "%s", logDir);

    if (init_log_mgr(mgr, 0, NULL)) {
        return -1;
    }

    st->log_mgr = (void *)mgr;

    return 0;
}

void stacktrace_destroy_log_mgr(struct stack_trace_s *st)
{
    if (!st->log_mgr) {
        return;
    }

    destroy_log_mgr(st->log_mgr);
    return;
}

#endif

#if 1
static int get_stack_map_fd(struct stack_trace_s *st)
{
    if (st->is_stackmap_a) {
        return st->stackmap_a_fd;
    } else {
        return st->stackmap_b_fd;
    }
}

static struct perf_buffer* get_pb(struct stack_trace_s *st, struct svg_stack_trace_s *svg_st)
{
    if (st->is_stackmap_a) {
        return svg_st->pb_a;
    } else {
        return svg_st->pb_b;
    }
}

#endif

#if 1   // Proc cache

static void __destroy_proc_cache(struct proc_cache_s *proc_cache)
{
    if (!proc_cache || !proc_cache->proc_symbs) {
        return;
    }

    proc_delete_all_symbs(proc_cache->proc_symbs);
    proc_cache->proc_symbs = NULL;
    return;
}

static void destroy_proc_cache_tbl(struct stack_trace_s *st)
{
    if (!st || !st->proc_cache) {
        return;
    }

    struct proc_cache_s *item, *tmp;
    H_ITER(st->proc_cache, item, tmp) {
        __destroy_proc_cache(item);
        H_DEL(st->proc_cache, item);
        (void)free(item);
    }
    st->proc_cache = NULL;
    (void)memset(st->proc_cache_mirro, 0, sizeof(struct proc_cache_s *) * PROC_CACHE_MAX_COUNT);
    return;
}

static int __aging_proc_cache(struct stack_trace_s *st, struct proc_cache_s *aging_item)
{
    struct proc_cache_s *item = NULL;
    H_FIND(st->proc_cache, &(aging_item->k), sizeof(struct stack_pid_s), item);
    if (item) {
        st->stats.count[STACK_STATS_PCACHE_DEL]++;
        __destroy_proc_cache(item);
        H_DEL(st->proc_cache, item);
        (void)free(item);
        return 0;
    }
    return -1;
}

static int __add_proc_cache_mirro(struct stack_trace_s *st, struct proc_cache_s *new_item)
{
    struct proc_cache_s *aging_item;
    if (st->proc_cache_mirro_count < PROC_CACHE_MAX_COUNT) {
        st->proc_cache_mirro[st->proc_cache_mirro_count] = new_item;
        st->proc_cache_mirro_count++;
        return 0;
    }

    aging_item = st->proc_cache_mirro[0];   // Aging based on the creation timing
    for (int i = 1; i < PROC_CACHE_MAX_COUNT; i++) {
        st->proc_cache_mirro[i - 1] = st->proc_cache_mirro[i];
    }

    st->proc_cache_mirro[PROC_CACHE_MAX_COUNT - 1] = new_item;
    return __aging_proc_cache(st, aging_item);
}

static struct proc_cache_s* __search_proc_cache(struct stack_trace_s *st, struct stack_pid_s *stack_pid)
{
    struct proc_cache_s *item = NULL;
    H_FIND(st->proc_cache, stack_pid, sizeof(struct stack_pid_s), item);
    return item;
}

static struct proc_cache_s* __create_proc_cache(struct stack_trace_s *st, struct stack_pid_s *stack_pid, int load_symbs)
{
    struct proc_cache_s *new_item;
    struct proc_symbs_s* proc_symbs;
    int ret;

    proc_symbs = new_proc_symbs(stack_pid->proc_id);
    if (proc_symbs == NULL) {
        return NULL;
    }

    if (load_symbs) {
        ret = proc_load_all_symbs(proc_symbs, st->elf_reader, stack_pid->proc_id, st->native_stack_flag);
        if (ret != 0) {
            return NULL;
        }
    }

    new_item = (struct proc_cache_s *)malloc(sizeof(struct proc_cache_s));
    if (!new_item) {
        return NULL;
    }

    (void)memcpy(&new_item->k, stack_pid, sizeof(struct stack_pid_s));
    new_item->proc_symbs = proc_symbs;
    H_ADD_KEYPTR(st->proc_cache, &new_item->k, sizeof(struct stack_pid_s), new_item);
    st->stats.count[STACK_STATS_PCACHE_CRT]++;

    if (__add_proc_cache_mirro(st, new_item)) {
        // The program continues.
        ERROR("[STACKPROBE]: Proc cache add failed.\n");
    }
    return new_item;
}

static void __update_proc_cache(struct proc_symbs_s *proc_symbs)
{
    struct mod_s *mod;

    for (int i = 0; i < proc_symbs->mods_count; i++) {
        mod = proc_symbs->mods[i];
        if (mod && mod->mod_type == MODULE_JVM) {
            mod->mod_symbs = update_symb_from_jvm_sym_file((const char *)mod->__mod_info.name);
            if (mod->mod_symbs != NULL && mod->mod_symbs->symbs_count != 0) {
                proc_symbs->need_update = 0;
            }
            break;
        }
    }
}

static int search_user_addr_symb(u64 addr, struct addr_symb_s *addr_symb, struct proc_cache_s* proc_cache, char *comm)
{
    if (!proc_cache || !proc_cache->proc_symbs) {
        return -1;
    }

    return proc_search_addr_symb(proc_cache->proc_symbs, addr, addr_symb, comm);
}

#endif

#if 1

static void clear_raw_stack_trace(struct svg_stack_trace_s *svg_st, char is_stackmap_a)
{
    if (!svg_st) {
        return;
    }
    if (is_stackmap_a) {
        svg_st->raw_stack_trace_a->raw_trace_count = 0;
    } else {
        svg_st->raw_stack_trace_b->raw_trace_count = 0;
    }
}

static struct raw_stack_trace_s *create_raw_stack_trace(struct stack_trace_s *st)
{
    struct raw_stack_trace_s *raw_stack_trace;

    size_t stack_size = st->cpus_num * MAX_PERCPU_SAMPLE_COUNT;
    size_t mem_size = sizeof(struct raw_stack_trace_s);
    mem_size += (stack_size * sizeof(struct raw_trace_s));

    raw_stack_trace = (struct raw_stack_trace_s *)malloc(mem_size);
    if (!raw_stack_trace) {
        return NULL;
    }
    (void)memset(raw_stack_trace, 0, mem_size);
    raw_stack_trace->stack_size = stack_size;
    return raw_stack_trace;
}

static int add_raw_stack_id(struct raw_stack_trace_s *raw_st, struct raw_trace_s *raw_stack)
{
    if (!raw_st) {
        return -1;
    }

    if (raw_st->raw_trace_count >= raw_st->stack_size) {
        return -1;
    }

    (void)memcpy(&(raw_st->raw_traces[raw_st->raw_trace_count]),
            raw_stack, sizeof(struct raw_trace_s));
    raw_st->raw_trace_count++;
    return 0;
}

#endif

#define STACK_LAYER_ELSE 0
#define STACK_LAYER_1ST 1
#define STACK_LAYER_2ND 2 // only for Java
#define STACK_LAYER_3RD 3 // only for Java

// For deep call stacks (especially prone to Java programs), it is easy to sample incomplete call stacks.
// If the function name at the first layer of the call stack contains ".",
// it means that this is must be an incomplete call stack.
// We query whether the first two layers of this call stack are contained in other call stacks (eg. A),
// and then count this call on the A call stack.
#if 1
static int stack_addrsymbs2string_incomplete(struct proc_symbs_s *proc_symbs, struct addr_symb_s *addr_symb,
                                             int *layer, char *p, int size)
{
    int ret;
    char *symb;
    if (size <= 0) {
        return -1;
    }

    char *cur_p = p;
    int len = size;

    if (addr_symb->sym == NULL) {
        return 0;
    }
    symb = addr_symb->sym;

    ret = __snprintf(&cur_p, len, &len, "; %s", symb);
    if (*layer == STACK_LAYER_1ST) {
        *layer = STACK_LAYER_2ND;
    } else if (*layer == STACK_LAYER_2ND) {
        *layer = STACK_LAYER_3RD;
    } else {
        return -1;
    }

    if (ret < 0) {
        return -1;
    }
    return size > len ? (size - len) : -1;
}

static int stack_addrsymbs2string(struct proc_symbs_s *proc_symbs, struct addr_symb_s *addr_symb,
                                  int *layer, char *p, int size)
{
    int ret;
    char *symb;
    if (size <= 0) {
        return -1;
    }

    char *cur_p = p;
    int len = size;

    if (addr_symb->sym == NULL) {
        return 0;
    }
    symb = addr_symb->sym;

    if (*layer == STACK_LAYER_1ST) {
        if (proc_symbs->pod[0] != 0) {
            ret = __snprintf(&cur_p, len, &len, "[Pod]%s; ", proc_symbs->pod);
        }
        if (proc_symbs->container_name[0] != 0) {
            ret = __snprintf(&cur_p, len, &len, "[Con]%s; ", proc_symbs->container_name);
        }
        ret = __snprintf(&cur_p, len, &len, "[%d]%s; %s", proc_symbs->proc_id, proc_symbs->comm, symb);
        *layer = STACK_LAYER_2ND;
    } else {
        ret = __snprintf(&cur_p, len, &len, "; %s", symb);
    }

    if (ret < 0) {
        return -1;
    }
    return size > len ? (size - len) : -1;
}

static int __stack_file2string(struct proc_symbs_s *proc_symbs, char *line, char *p, int size, s64 *count)
{
    int ret = 0;
    if (size <= 0) {
        return -1;
    }

    char *cur_p = p;
    int len = size;

    if (line == NULL) {
        return 0;
    }

    *count = 0;
    int line_len = strlen(line);
    if (line_len >= size || line_len <= 3) {
        return 0;
    }
    for (int i = line_len - 2; i > 0; i--) {
        if (line[i] == ' ') {
            *count = atoi(line + i + 1);
            line[i] = 0;
            break;
        }
    }

    if (*count == 0) {
        return 0;
    }

    cur_p[0] = 0;
    if (proc_symbs->pod[0] != 0) {
        ret = __snprintf(&cur_p, len, &len, "[Pod]%s; ", proc_symbs->pod);
        if (ret < 0) {
            return -1;
        }
    }


    if (proc_symbs->container_name[0] != 0) {
        ret = __snprintf(&cur_p, len, &len, "[Con]%s; ", proc_symbs->container_name);
        if (ret < 0) {
            return -1;
        }
    }

    ret = __snprintf(&cur_p, len, &len, "[%d]%s; %s", proc_symbs->proc_id, proc_symbs->comm, line);
    if (ret < 0) {
        return -1;
    }

    return size > len ? (size - len) : -1;
}

static int __stack_symbs2string(struct stack_symbs_s *stack_symbs, struct proc_symbs_s *proc_symbs,
                                char symbos_str[], size_t size, int incomplete_stack_flag)
{
    int len;
    int layer = STACK_LAYER_1ST;
    int remain_len = size;
    char *pos = symbos_str;
    struct addr_symb_s *addr_symb;

    for (int i = 0; i < PERF_MAX_STACK_DEPTH; i++) {
        addr_symb = &(stack_symbs->user_stack_symbs[i]);
        if (addr_symb->orign_addr == 0) {
            continue;
        }
        if (incomplete_stack_flag) {
            len = stack_addrsymbs2string_incomplete(proc_symbs, addr_symb, &layer, pos, remain_len);
            if (layer == STACK_LAYER_3RD) {
                return -1;
            }
        } else {
            len = stack_addrsymbs2string(proc_symbs, addr_symb, &layer, pos, remain_len);
        }
        if (len < 0) {
            return -1;
        }
        remain_len -= len;
        pos += len;
    }

    symbos_str[size - 1] = 0;
    return 0;
}

static s64 convert_real_count(struct stack_trace_s *st, enum stack_svg_type_e en_type, s64 origin_count)
{
    if (en_type == STACK_SVG_OFFCPU) {
        return origin_count / st->post_server.perf_sample_period;
    }

    return  origin_count;
}

static struct proc_stack_trace_histo_s *get_proc_histo_item(struct svg_stack_trace_s *svg_st, int proc_id)
{
    struct proc_stack_trace_histo_s *proc_histo = NULL;
    H_FIND_I(svg_st->proc_histo_tbl, &proc_id, proc_histo);
    return proc_histo;
}

static struct proc_stack_trace_histo_s *add_proc_histo_item(struct svg_stack_trace_s *svg_st, int proc_id,
    enum proc_stack_type_e proc_stack_type)
{
    struct proc_stack_trace_histo_s *new_proc_item =
        (struct proc_stack_trace_histo_s *)malloc(sizeof(struct proc_stack_trace_histo_s));
    if (!new_proc_item) {
        return NULL;
    }
    new_proc_item->proc_id = proc_id;
    new_proc_item->proc_stack_type = proc_stack_type;
    new_proc_item->histo_tbl = NULL;
    H_ADD_I(svg_st->proc_histo_tbl, proc_id, new_proc_item);

    return new_proc_item;
}

static int add_stack_symbs_str(struct stack_trace_s *st, struct proc_stack_trace_histo_s *proc_histo,
    char *str, s64 count)
{
    struct stack_trace_histo_s *item = NULL;
    struct stack_trace_histo_s *new_item = NULL;

    H_FIND_S(proc_histo->histo_tbl, str, item);
    if (item) {
        st->stats.count[STACK_STATS_HISTO_FOLDED]++;
        item->count = (s64)item->count + count;
        return 0;
    }

    new_item = (struct stack_trace_histo_s *)malloc(sizeof(struct stack_trace_histo_s));
    if (!new_item) {
        return -1;
    }
    new_item->stack_symbs_str[0] = 0;
    (void)snprintf(new_item->stack_symbs_str, sizeof(new_item->stack_symbs_str), "%s", str);
    new_item->count = count < 0 ? 0 : count;
    if (new_item->count != 0) {
        H_ADD_S(proc_histo->histo_tbl, stack_symbs_str, new_item);
    }

    return 0;
}

static char *stack_tmp_files[STACK_SVG_MAX] = {
    "stacks-oncpu.txt",
    "stacks-offcpu.txt",
    "stacks-mem.txt",
    "stacks-io.txt"
};

static int add_stack_histo_from_file(struct stack_trace_s *st, struct proc_histo_tmp_s *proc_histo_tmp)
{
    enum stack_svg_type_e en_type = proc_histo_tmp->en_type;
    struct proc_stack_trace_histo_s *proc_histo = proc_histo_tmp->proc_histo;
    struct proc_symbs_s *proc_symbs = proc_histo_tmp->proc_symbs;

    char stack_file[LINE_BUF_LEN];
    FILE *stack_fp;

    // /proc/<pid>/root/tmp/java-data-<pid>/stacks-mem.txt
    int ret = get_host_java_tmp_file(proc_symbs->proc_id,
        stack_tmp_files[en_type], stack_file, LINE_BUF_LEN);
    if (ret != 0) {
        ERROR("[FLAMEGRAPH]: get java proc stack tmp file failed: %s\n", stack_file);
        return -1;
    }

    stack_fp = fopen(stack_file, "rb");
    if(!stack_fp) {
        ERROR("[FLAMEGRAPH]: fopen java proc stack tmp file failed: %s\n", stack_file);
        return -1;
    }

    proc_histo->proc_stack_type = PROC_STACK_STORE_READED;
    int len;
    char line[STACK_SYMBS_LEN];
    line[0] = 0;
    char str[STACK_SYMBS_LEN];
    s64 count;
    while (fgets(line, sizeof(line), stack_fp)) {
        len = __stack_file2string(proc_symbs, line, str, STACK_SYMBS_LEN, &count);
        if (len < 0) {
            return -1;
        }
        add_stack_symbs_str(st, proc_histo, str, count);
    }

    fclose(stack_fp);
    return 0;
}

static int add_stack_histo_from_hash(struct stack_trace_s *st, struct stack_symbs_s *stack_symbs,
    struct proc_histo_tmp_s *proc_histo_tmp, s64 origin_count)
{
    char str[STACK_SYMBS_LEN];
    struct stack_trace_histo_s *tmp;
    struct stack_trace_histo_s *item = NULL;
    int incomplete_stack_flag = 0;
    enum stack_svg_type_e en_type = proc_histo_tmp->en_type;
    struct proc_stack_trace_histo_s *proc_histo = proc_histo_tmp->proc_histo;
    struct proc_symbs_s *proc_symbs = proc_histo_tmp->proc_symbs;

    if (stack_symbs->user_stack_symbs[PERF_MAX_STACK_DEPTH - 1].orign_addr != 0) {
        incomplete_stack_flag = 1;
    }

    str[0] = 0;
    if (__stack_symbs2string(stack_symbs, proc_symbs, str, STACK_SYMBS_LEN, incomplete_stack_flag)) {
        // Statistic error, but program continues
        st->stats.count[STACK_STATS_HISTO_ERR]++;
    }

    s64 count = convert_real_count(st, en_type, origin_count);
    if (str[0] == 0) {
        DEBUG("[STACKPROBE]: symbs2str is null(proc = %d).\n",
                stack_symbs->pid.proc_id);
        return -1;
    }

    // incomplete call stack merge
    if (incomplete_stack_flag) {
        char tmp_str[__FUNC_NAME_LEN] = {0};
        (void)snprintf(tmp_str, __FUNC_NAME_LEN, "[%d]", proc_symbs->proc_id);

        H_ITER(proc_histo->histo_tbl, item, tmp) {
            if (strstr(item->stack_symbs_str, tmp_str) && strstr(item->stack_symbs_str, str)) {
                st->stats.count[STACK_STATS_HISTO_FOLDED]++;
                item->count = item->count + count;
                return 0;
            }
        }
        return -1;
    }

    return add_stack_symbs_str(st, proc_histo, str, count);
}

static int add_stack_histo(struct stack_trace_s *st, struct stack_symbs_s *stack_symbs,
    struct proc_histo_tmp_s *proc_histo_tmp, s64 origin_count)
{
    if (proc_histo_tmp->load_symbs) {
        add_stack_histo_from_hash(st, stack_symbs, proc_histo_tmp, origin_count);
    } else {
        add_stack_histo_from_file(st, proc_histo_tmp);
    }

    return 0;
}

static void clear_stack_histo(struct svg_stack_trace_s *svg_st)
{
    if (!svg_st || !svg_st->proc_histo_tbl) {
        return;
    }

    struct proc_stack_trace_histo_s *proc_histo, *proc_tmp;
    struct stack_trace_histo_s *item, *tmp;
    H_ITER(svg_st->proc_histo_tbl, proc_histo, proc_tmp) {
        if (proc_histo->histo_tbl != NULL) {
            H_ITER(proc_histo->histo_tbl, item, tmp) {
                H_DEL(proc_histo->histo_tbl, item);
                (void)free(item);
            }
            proc_histo->histo_tbl = NULL;
        }
        H_DEL(svg_st->proc_histo_tbl, proc_histo);
        (void)free(proc_histo);
    }
    svg_st->proc_histo_tbl = NULL;
}

#endif

#if 1
static int stack_id2symbs_user(struct stack_trace_s *st, struct stack_id_s *stack_id,
                               struct addr_symb_s usr_stack_symbs[], struct proc_cache_s* proc_cache, size_t size)
{
    int index = 0;
    u64 ip[PERF_MAX_STACK_DEPTH] = {0};
    int fd = get_stack_map_fd(st);

    if (bpf_map_lookup_elem(fd, &(stack_id->user_stack_id), ip) != 0) {
        DEBUG("[STACKPROBE]: Failed to id2symbs user stack(map_lkup).\n");
        st->stats.count[STACK_STATS_MAP_LKUP_ERR]++;
        return -1;
    }

    for (int i = PERF_MAX_STACK_DEPTH - 1; (i >= 0 && index < size); i--) {
        if (ip[i] != 0 && IS_IEG_ADDR(ip[i])) {
            if (search_user_addr_symb(ip[i], &(usr_stack_symbs[index]), proc_cache, stack_id->comm)) {
                DEBUG("[STACKPROBE]: Failed to id2symbs user stack(%s[0x%llx]).\n",
                    stack_id->comm, ip[i]);
                st->stats.count[STACK_STATS_USR_ADDR_ERR]++;
                usr_stack_symbs[index].mod = stack_id->comm;
            } else {
                st->stats.count[STACK_STATS_USR_ADDR]++;
            }
            index++;
        }
    }
    return 0;
}

#define __CPU_IDLE  "do_idle"
static char __is_cpu_idle(struct addr_symb_s *addr_symb)
{
    if (addr_symb && addr_symb->sym && !strcmp(addr_symb->sym, __CPU_IDLE)) {
        return 1;
    }
    return 0;
}

static int stack_id2symbs_kern(struct stack_trace_s *st, u32 kern_stack_id,
                                struct addr_symb_s kern_stack_symbs[], size_t size)
{
    int index = 0;
    u64 ip[PERF_MAX_STACK_DEPTH] = {0};
    int fd = get_stack_map_fd(st);

    if (bpf_map_lookup_elem(fd, &kern_stack_id, ip) != 0) {
        DEBUG("[STACKPROBE]: Failed to id2symbs kern stack(stack_id = %u).\n", kern_stack_id);
        st->stats.count[STACK_STATS_MAP_LKUP_ERR]++;
        return -1;
    }

    for (int i = PERF_MAX_STACK_DEPTH - 1; (i >= 0 && index < size); i--) {
        if (ip[i] != 0 && IS_IEG_ADDR(ip[i])) {
            if (search_kern_addr_symb(st->ksymbs, ip[i], &(kern_stack_symbs[index]))) {
                DEBUG("[STACKPROBE]: Failed to id2symbs kern stack(0x%llx).\n", ip[i]);
                st->stats.count[STACK_STATS_KERN_ADDR_ERR]++;
            } else {
                st->stats.count[STACK_STATS_KERN_ADDR]++;
            }

            if (__is_cpu_idle(&kern_stack_symbs[index])) {
                return 1;   // ignore cpu idle
            }

            index++;
        }
    }
    return 0;
}

static int stack_id2symbs(struct stack_trace_s *st, struct stack_id_s *stack_id, struct proc_cache_s* proc_cache,
                          struct stack_symbs_s *stack_symbs)
{
    int ret;
    (void)memcpy(&(stack_symbs->pid), &(stack_id->pid), sizeof(struct stack_pid_s));

    if (stack_id->kern_stack_id >= 0) {
        ret = stack_id2symbs_kern(st, stack_id->kern_stack_id,
                    stack_symbs->kern_stack_symbs, PERF_MAX_STACK_DEPTH);
        if (ret) {
            return ret;
        }
    }

    if (stack_id->user_stack_id >= 0) {
        if (stack_id2symbs_user(st, stack_id,
                stack_symbs->user_stack_symbs, proc_cache, PERF_MAX_STACK_DEPTH)) {
            return -1;
        }
    }

    if ((stack_id->user_stack_id >= 0) && (stack_id->kern_stack_id >= 0)) {
        st->stats.count[STACK_STATS_USR_KERN_ADDR]++;
    }

    return 0;
}

static u64 __stack_count_symb(struct stack_trace_s *st)
{
    int i;
    u64 count = 0;
    struct mod_s* mod;
    struct proc_cache_s *item, *tmp;

    H_ITER(st->proc_cache, item, tmp) {
        if (!item->proc_symbs) {
            continue;
        }

        for (i = 0; i < item->proc_symbs->mods_count; i++) {
            mod = item->proc_symbs->mods[i];
            if (mod && mod->mod_symbs) {
                count += (u64)mod->mod_symbs->symbs_count;
            }

            if (mod && mod->debug_symbs) {
                count += (u64)mod->debug_symbs->symbs_count;
            }
            item->proc_symbs->need_update = 1; // periodic update JVM symbs
        }
    }
    return count;
}

static struct proc_cache_s* __get_proc_cache(struct stack_trace_s *st, struct stack_pid_s *stack_pid, int load_symbs)
{
    struct proc_cache_s* proc_cache;

    proc_cache = __search_proc_cache(st, stack_pid);
    if (!proc_cache) {
        proc_cache = __create_proc_cache(st, stack_pid, load_symbs);
    } else if (load_symbs && proc_cache->proc_symbs->need_update) {
        __update_proc_cache(proc_cache->proc_symbs);
    }

    return proc_cache;
}

static int stack_id2histogram(struct stack_trace_s *st, enum stack_svg_type_e en_type, char is_stackmap_a)
{
    int ret;
    struct stack_id_s *stack_id;
    struct stack_symbs_s stack_symbs;
    struct raw_stack_trace_s *raw_st;
    struct proc_cache_s* proc_cache;
    struct proc_stack_trace_histo_s *proc_histo;
    struct svg_stack_trace_s *svg_st = st->svg_stack_traces[en_type];
    int load_symbs; // Indicates whether to read the process symbol table or read the symbolic call stack file directly

    if (!svg_st) {
        return -1;
    }
    if (is_stackmap_a) {
        raw_st = svg_st->raw_stack_trace_a;
    } else {
        raw_st = svg_st->raw_stack_trace_b;
    }
    if (raw_st == NULL) { 
        return -1;
    }
    
    int rt_count = raw_st->raw_trace_count;
    for (int i = 0; i < rt_count; i++) {
        if (g_stop) {
            break;
        }
        stack_id = &(raw_st->raw_traces[i].stack_id);
        proc_histo = get_proc_histo_item(svg_st, stack_id->pid.proc_id);
        if (proc_histo != NULL) {
            if (proc_histo->proc_stack_type == PROC_STACK_STORE_IN_HASH) {
                load_symbs = 1;
            } else if (proc_histo->proc_stack_type == PROC_STACK_STORE_IN_FILE) {
                load_symbs = 0;
            } else {
                // PROC_STACK_STORE_READED means that the symbolic call stack of this process has been read within 30s
                continue;
            }
        } else {
            proc_histo = add_proc_histo_item(svg_st, stack_id->pid.proc_id, PROC_STACK_STORE_IN_HASH);
            if (proc_histo == NULL) {
                return -1;
            }
            load_symbs = 1;
        }

        proc_cache = __get_proc_cache(st, &(stack_id->pid), load_symbs);
        if (!proc_cache) {
            continue;
        }

        // None of the members is empty
        struct proc_histo_tmp_s proc_histo_tmp = {
            .en_type = en_type,
            .load_symbs = load_symbs,
            .proc_symbs = proc_cache->proc_symbs,
            .proc_histo = proc_histo
        };
        if (load_symbs) {
            (void)memset(&stack_symbs, 0, sizeof(stack_symbs));
            ret = stack_id2symbs(st, stack_id, proc_cache, &stack_symbs);
            if (ret != 0) {
                continue;
            }
            st->stats.count[STACK_STATS_ID2SYMBS]++;
            (void)add_stack_histo(st, &stack_symbs, &proc_histo_tmp, raw_st->raw_traces[i].count);
        } else {
            (void)add_stack_histo(st, NULL, &proc_histo_tmp, 0);
        }
    }

    st->stats.count[STACK_STATS_P_CACHE] = H_COUNT(st->proc_cache);
    st->stats.count[STACK_STATS_SYMB_CACHE] = __stack_count_symb(st);
    return 0;
}

#endif

static char is_tmout(struct stack_trace_s *st)
{
    time_t current = (time_t)time(NULL);
    time_t secs;

    if (current > st->running_times) {
        secs = current - st->running_times;
        if (secs >= TMOUT_PERIOD) {
            st->running_times = current;
            return 1;
        }
    }
    return 0;
}

static void process_loss_data(void *ctx, int cpu, u64 cnt)
{
    if (!g_st) {
        return;
    }
    g_st->stats.count[STACK_STATS_LOSS] += cnt;
}

static void process_oncpu_raw_stack_trace(void *ctx, int cpu, void *data, u32 size)
{
    struct raw_stack_trace_s *raw_st;
    if (!g_st || !g_st->svg_stack_traces[STACK_SVG_ONCPU] || !data) {
        return;
    }

    if (g_st->is_stackmap_a) {
        raw_st = g_st->svg_stack_traces[STACK_SVG_ONCPU]->raw_stack_trace_a;
    } else {
        raw_st = g_st->svg_stack_traces[STACK_SVG_ONCPU]->raw_stack_trace_b;
    }

    if (!raw_st) {
        return;
    }

    if (add_raw_stack_id(raw_st, (struct raw_trace_s *)data)) {
        g_st->stats.count[STACK_STATS_LOSS]++;
    } else {
        g_st->stats.count[STACK_STATS_RAW]++;
    }

    return;
}

static void process_offcpu_raw_stack_trace(void *ctx, int cpu, void *data, u32 size)
{
    struct raw_stack_trace_s *raw_st;
    if (!g_st || !g_st->svg_stack_traces[STACK_SVG_OFFCPU] || !data) {
        return;
    }

    if (g_st->is_stackmap_a) {
        raw_st = g_st->svg_stack_traces[STACK_SVG_OFFCPU]->raw_stack_trace_a;
    } else {
        raw_st = g_st->svg_stack_traces[STACK_SVG_OFFCPU]->raw_stack_trace_b;
    }

    if (!raw_st) {
        return;
    }

    if (add_raw_stack_id(raw_st, (struct raw_trace_s *)data)) {
        g_st->stats.count[STACK_STATS_LOSS]++;
    } else {
        g_st->stats.count[STACK_STATS_RAW]++;
    }

    return;
}


static void process_mem_raw_stack_trace(void *ctx, int cpu, void *data, u32 size)
{
    struct raw_stack_trace_s *raw_st;
    if (!g_st || !g_st->svg_stack_traces[STACK_SVG_MEM] || !data) {
        return;
    }

    if (g_st->is_stackmap_a) {
        raw_st = g_st->svg_stack_traces[STACK_SVG_MEM]->raw_stack_trace_a;
    } else {
        raw_st = g_st->svg_stack_traces[STACK_SVG_MEM]->raw_stack_trace_b;
    }

    if (!raw_st) {
        return;
    }

    if (add_raw_stack_id(raw_st, (struct raw_trace_s *)data)) {
        g_st->stats.count[STACK_STATS_LOSS]++;
    } else {
        g_st->stats.count[STACK_STATS_RAW]++;
    }

    return;
}

static void destroy_svg_stack_trace(struct svg_stack_trace_s **ptr_svg_st)
{
    struct svg_stack_trace_s *svg_st = *ptr_svg_st;

    if (svg_st->wr_flame_thd > 0) {
        (void)pthread_cancel(svg_st->wr_flame_thd);
    }

    *ptr_svg_st = NULL;
    if (!svg_st) {
        return;
    }

    if (svg_st->obj) {
        bpf_object__close(svg_st->obj);
        svg_st->obj = NULL;
    }

    if (svg_st->pb_a) {
        perf_buffer__free(svg_st->pb_a);
        svg_st->pb_a = NULL;
        
    }
    if (svg_st->pb_b) {
        perf_buffer__free(svg_st->pb_b);
        svg_st->pb_b = NULL;
    }
    if (svg_st->svg_mng) {
        destroy_svg_mng(svg_st->svg_mng);
        svg_st->svg_mng = NULL;
    }
    if (svg_st->raw_stack_trace_a) {
        (void)free(svg_st->raw_stack_trace_a);
        svg_st->raw_stack_trace_a = NULL;
    }
    if (svg_st->raw_stack_trace_b) {
        (void)free(svg_st->raw_stack_trace_b);
        svg_st->raw_stack_trace_b = NULL;
    }
    clear_stack_histo(svg_st);

    (void)free(svg_st);
    return;
}

static void destroy_stack_trace(struct stack_trace_s **ptr_st)
{
    struct stack_trace_s *st = *ptr_st;
    *ptr_st = NULL;
    if (!st) {
        return;
    }

    if (st->post_server.post_enable) {
        clean_post_server();
    }

    for (int cpu = 0; cpu < st->cpus_num; cpu++) {
        if (st->pmu_fd[cpu] > 0) {
            ioctl(st->pmu_fd[cpu], PERF_EVENT_IOC_DISABLE);
            close(st->pmu_fd[cpu]);
        }
    }

    for (int i = 0; i < STACK_SVG_MAX; i++) {
        if (st->svg_stack_traces[i] == NULL) {
            continue;
        }
        destroy_svg_stack_trace(&st->svg_stack_traces[i]);
    }
    
    if (st->ksymbs) {
        destroy_ksymbs_tbl(st->ksymbs);
        (void)free(st->ksymbs);
    }

    destroy_proc_cache_tbl(st);

    if (st->elf_reader) {
        destroy_elf_reader(st->elf_reader);
    }

    deinit_elf_symbs();

    stacktrace_destroy_log_mgr(st);

    (void)free(st);
    return;
}

static struct svg_stack_trace_s *create_svg_stack_trace(struct ipc_body_s *ipc_body, const char *flame_name)
{
    struct svg_stack_trace_s *svg_st = (struct svg_stack_trace_s *)malloc(sizeof(struct svg_stack_trace_s));
    if (!svg_st) {
        return NULL;
    }
    memset(svg_st, 0, sizeof(struct svg_stack_trace_s));

    svg_st->svg_mng = create_svg_mng(ipc_body->probe_param.svg_period);
    if (!svg_st->svg_mng) {
        goto cleanup;
    }

    if (set_svg_dir(&svg_st->svg_mng->svg, ipc_body->probe_param.svg_dir, flame_name)) {
        goto cleanup;
    }

    if (set_flame_graph_path(svg_st->svg_mng, ipc_body->probe_param.flame_dir, flame_name)) {
        goto cleanup;
    }

    svg_st->raw_stack_trace_a = create_raw_stack_trace(g_st);
    if (!svg_st->raw_stack_trace_a) {
        goto cleanup;
    }
    svg_st->raw_stack_trace_b = create_raw_stack_trace(g_st);
    if (!svg_st->raw_stack_trace_b) {
        goto cleanup;
    }

    INFO("[STACKPROBE]: create %s svg stack trace succeed.\n", flame_name);
    return svg_st;
cleanup:
    destroy_svg_stack_trace(&svg_st);
    return NULL;
}


static struct stack_trace_s *create_stack_trace(struct ipc_body_s *ipc_body)
{
    int cpus_num = NR_CPUS;
    size_t size = sizeof(struct stack_trace_s) + cpus_num * sizeof(int);
    struct stack_trace_s *st = (struct stack_trace_s *)malloc(size);
    if (!st) {
        return NULL;
    }

    (void)memset(st, 0, size);
    st->cpus_num = cpus_num;
    st->whitelist_enable = 1; // Only the flame graph of the specified process is collected
    st->multi_instance_flag = ipc_body->probe_param.multi_instance_flag;
    st->native_stack_flag = ipc_body->probe_param.native_stack_flag;
#if 0
    if (stacktrace_create_log_mgr(st, conf->generalConfig->logDir)) {
        goto err;
    }
#endif

    if (set_post_server(&st->post_server, ipc_body->probe_param.pyroscope_server,
                        ipc_body->probe_param.perf_sample_period, ipc_body->probe_param.multi_instance_flag) != 0) {
        INFO("[STACKPROBE]: Do not post to Pyroscope Server.\n");
        st->post_server.post_enable = 0;
    } else {
        if (get_system_uuid(st->post_server.app_suffix, APP_SUFFIX_LEN) != 0) {
            st->post_server.app_suffix[0] = 0;
        }
        INFO("[STACKPROBE]: Will post to Pyroscope Server: %s.\n", ipc_body->probe_param.pyroscope_server);
    }

    st->elf_reader = create_elf_reader(DEBUG_DIR);
    if (!st->elf_reader) {
        goto err;
    }

    st->ksymbs = create_ksymbs_tbl();
    if (!st->ksymbs) {
        goto err;
    }

    if (load_kern_syms(st->ksymbs)) {
        ERROR("[STACKPROBE]: Failed to load kern symbols.\n");
        goto err;
    }

    (void)sort_kern_syms(st->ksymbs);

    st->running_times = (time_t)time(NULL);
    st->is_stackmap_a = ((st->convert_stack_count % 2) == 0);

    INFO("[STACKPROBE]: whitelist %s\n", st->whitelist_enable ? "enable" : "disable");
    INFO("[STACKPROBE]: create stack trace succeed(cpus_num = %d, kern_symbols = %u).\n",
        st->cpus_num, st->ksymbs->ksym_size);
    return st;

err:
    destroy_stack_trace(&st);
    return NULL;
}

static void update_convert_counter()
{
    u32 key = 0;
    int ret;
    struct convert_data_t val = {0};

    ret = bpf_map_lookup_elem(g_st->convert_map_fd, &key, &val);
    if (ret == 0) {
        val.convert_counter = g_st->convert_stack_count;
        (void)bpf_map_update_elem(g_st->convert_map_fd, &key, &val, BPF_ANY);
    }
}

static void init_convert_counter()
{
    u32 key = 0;
    if (!g_st || (g_st->convert_map_fd <= 0)) {
        ERROR("[STACKPROBE]: Init convert counter failed!\n");
        return;
    }
    struct convert_data_t convert_data = {
        .whitelist_enable = g_st->whitelist_enable,
        .convert_counter = g_st->convert_stack_count};
    (void)bpf_map_update_elem(g_st->convert_map_fd, &key, &convert_data, BPF_ANY);
}

static int load_bpf_prog(struct svg_stack_trace_s *svg_st, const char *prog_name)
{
    int ret;
    struct bpf_program *prog;

    svg_st->obj = bpf_object__open_file(prog_name, NULL);
    ret = libbpf_get_error(svg_st->obj);
    if (ret) {
        ERROR("[STACKPROBE]: opening BPF object file failed(err = %d).\n", ret);
        goto err;
    }

    ret = BPF_OBJ_PIN_MAP_PATH(svg_st->obj, "proc_obj_map", STACK_PROC_MAP_PATH);
    if (ret) {
        ERROR("[STACKPROBE]: Failed to pin proc_obj_map map(err = %d).\n", ret);
        goto err;
    }
    ret = BPF_OBJ_PIN_MAP_PATH(svg_st->obj, "convert_map", STACK_CONVERT_PATH);
    if (ret) {
        ERROR("[STACKPROBE]: Failed to pin convert_map map(err = %d).\n", ret);
        goto err;
    }
    ret = BPF_OBJ_PIN_MAP_PATH(svg_st->obj, "stackmap_a", STACK_STACKMAPA_PATH);
    if (ret) {
        ERROR("[STACKPROBE]: Failed to pin stackmap_a map(err = %d).\n", ret);
        goto err;
    }
    ret = BPF_OBJ_PIN_MAP_PATH(svg_st->obj, "stackmap_b", STACK_STACKMAPB_PATH);
    if (ret) {
        ERROR("[STACKPROBE]: Failed to pin stackmap_b map(err = %d).\n", ret);
        goto err;
    }

    ret = bpf_object__load(svg_st->obj);
    if (ret) {
        ERROR("[STACKPROBE]: Failed to load bpf prog(err = %d).\n", ret);
        goto err;
    }

#if (CURRENT_LIBBPF_VERSION  < LIBBPF_VERSION(0, 7)) 
    prog = bpf_program__next(NULL, svg_st->obj);
#else
    prog = bpf_object__next_program(svg_st->obj, NULL);
#endif
    if (prog == NULL) {
        ERROR("[STACKPROBE]: Cannot find bpf_prog.\n");
        goto err;
    }
    svg_st->bpf_prog_fd = bpf_program__fd(prog);
    if (g_st->convert_map_fd == 0) {
        g_st->convert_map_fd = BPF_OBJ_GET_MAP_FD(svg_st->obj, "convert_map");
        g_st->proc_obj_map_fd = BPF_OBJ_GET_MAP_FD(svg_st->obj, "proc_obj_map");
        g_st->stackmap_a_fd = BPF_OBJ_GET_MAP_FD(svg_st->obj, "stackmap_a");
        g_st->stackmap_b_fd = BPF_OBJ_GET_MAP_FD(svg_st->obj, "stackmap_b");
    }
    svg_st->stackmap_perf_a_fd = BPF_OBJ_GET_MAP_FD(svg_st->obj, "stackmap_perf_a");
    svg_st->stackmap_perf_b_fd = BPF_OBJ_GET_MAP_FD(svg_st->obj, "stackmap_perf_b");

    INFO("[STACKPROBE]: load bpf prog succeed(%s).\n", prog_name);
    return 0;

err:
    return -1;
}

static int create_perf(struct svg_stack_trace_s *svg_st, perf_buffer_sample_fn cb)
{
    if (cb == NULL) {
        return 0;
    }
    svg_st->pb_a = create_pref_buffer2(svg_st->stackmap_perf_a_fd, cb, process_loss_data);
    if (!svg_st->pb_a) {
        goto err;
    }

    svg_st->pb_b = create_pref_buffer2(svg_st->stackmap_perf_b_fd, cb, process_loss_data);
    if (!svg_st->pb_b) {
        goto err;
    }
    INFO("[STACKPROBE]: create perf succeed.\n");
    return 0;

err:
    return -1;
}

static int attach_oncpu_bpf_prog(struct ipc_body_s *ipc_body, struct svg_stack_trace_s *svg_st)
{
    int ret;
    int perf_sample_period = ipc_body->probe_param.perf_sample_period;

    if (perf_sample_period == 0) {
        perf_sample_period = 10;
    }
    struct perf_event_attr attr_type_sw = {
        .sample_freq = perf_sample_period, // default 10ms
        .freq = 1,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_CPU_CLOCK,
    };

    for (int cpu = 0; cpu < g_st->cpus_num; cpu++) {
        g_st->pmu_fd[cpu] = perf_event_open(&attr_type_sw, -1, cpu, -1, 0);
        if (g_st->pmu_fd[cpu] < 0) {
            ERROR("[STACKPROBE]: Failed open perf event.\n");
            goto err;
        }

        ret = ioctl(g_st->pmu_fd[cpu], PERF_EVENT_IOC_ENABLE, 0);
        if (ret) {
            ERROR("[STACKPROBE]: Failed to PERF_EVENT_IOC_ENABLE(err = %d).\n", ret);
            goto err;
        }

        ret = ioctl(g_st->pmu_fd[cpu], PERF_EVENT_IOC_SET_BPF, svg_st->bpf_prog_fd);
        if (ret) {
            ERROR("[STACKPROBE]: Failed to PERF_EVENT_IOC_SET_BPF(err = %d).\n", ret);
            goto err;
        }

        INFO("[STACKPROBE]: attach oncpu bpf succeed(cpu = %d).\n", cpu);
    }

    return 0;

err:
    return -1;
}

static int attach_offcpu_bpf_prog(struct ipc_body_s *ipc_body, struct svg_stack_trace_s *svg_st)
{
    int err;

    int i = 0;
    struct bpf_program *prog;
    struct bpf_link *links;
    bpf_object__for_each_program(prog, svg_st->obj) {
        links = bpf_program__attach(prog);
        err = libbpf_get_error(links);
        if (err) {
            ERROR("[STACKPROBE]: attach offcpu bpf failed %d\n", err);
            links = NULL;
            goto cleanup;
        }
        i++;
    }

    INFO("[STACKPROBE]: attach offcpu bpf succeed.\n");
    return 0;

cleanup:
    bpf_link__destroy(links);
    return -1;
}
#if 0
static void set_pids_inactive()
{
    struct bpf_link_hash_t *item, *tmp;
    if (bpf_link_head == NULL) {
        return;
    }
    
    H_ITER(bpf_link_head, item, tmp) {
        item->v.pid_state = PID_NOEXIST;
    }
}

static int add_bpf_link(unsigned int pidd)
{
    struct bpf_link_hash_t *item = malloc(sizeof(struct bpf_link_hash_t));
    if (item == NULL) {
        fprintf(stderr, "malloc bpf link %u failed\n", pidd);
        return -1;
    }
    (void)memset(item, 0, sizeof(struct bpf_link_hash_t));
    if (get_elf_path(pidd, item->v.elf_path, MAX_PATH_LEN, "libc\\.so") != CONTAINER_OK) {
        free(item);
        return -1;
    }

    item->pid = pidd;
    item->v.pid_state = PID_ELF_TOBE_ATTACHED;
    H_ADD(bpf_link_head, pid, sizeof(unsigned int), item);

    return 0;
}

static struct bpf_link_hash_t* find_bpf_link(unsigned int pid)
{
    struct bpf_link_hash_t *item = NULL;

    if (bpf_link_head == NULL) {
        return NULL;
    }
    H_FIND(bpf_link_head, &pid, sizeof(unsigned int), item);
    if (item == NULL) {
        return NULL;
    }

    if (item->v.bpf_links[0] == NULL) {
        item->v.pid_state = PID_ELF_TOBE_ATTACHED;
    } else {
        item->v.pid_state = PID_ELF_ATTACHED;
    }

    return item;
}

/*
[root@localhost ~]# ps -e -o pid,comm | grep gaussdb | awk '{print $1}'
*/
static int add_pids()
{
    unsigned int pid = 0;
    int ret = 0;
    int proc_obj_map_fd = g_st->proc_obj_map_fd;
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
        if (!find_bpf_link(pid)) {
            if (add_bpf_link(pid) != 0) {
                ERROR("[STACKPROBE]: add pid %u failed\n", pid);
            } else {
                INFO("[STACKPROBE]: add of pid %u success\n", pid);
            }
        }
    }

    return ret;
}

static void clear_invalid_pids()
{
    struct bpf_link_hash_t *pid_bpf_links, *tmp;
    if (bpf_link_head == NULL) {
        return;
    }
    H_ITER(bpf_link_head, pid_bpf_links, tmp) {
        if (pid_bpf_links->v.pid_state == PID_NOEXIST) {
            INFO("[STACKPROBE]: clear bpf link of pid %u\n", pid_bpf_links->pid);
            H_DEL(bpf_link_head, pid_bpf_links);
            (void)free(pid_bpf_links);
        }
    }
    
}

static bool get_bpf_prog(struct bpf_program *prog, char func_sec[], int func_len)
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

static void unload_bpf_progs(struct svg_stack_trace_s *svg_st)
{
    struct bpf_link_hash_t *pid_bpf_links, *tmp;
    if (bpf_link_head == NULL) {
        return;
    }

    H_ITER(bpf_link_head, pid_bpf_links, tmp) {
        if (pid_bpf_links->v.pid_state == PID_ELF_ATTACHED) {
            for (int i = 0; i < pid_bpf_links->v.bpf_link_num; i++) {
                bpf_link__destroy(pid_bpf_links->v.bpf_links[i]);
            }
            H_DEL(bpf_link_head, pid_bpf_links);
            (void)free(pid_bpf_links);
            INFO("[STACKPROBE]: detach mem bpf to pid %u success\n", pid_bpf_links->pid);
        }
    }
}

#define BPF_FUNC_NAME_LEN 32
static void *__uprobe_attach_check(void *arg)
{
    int err = 0;
    int i;
    struct bpf_link_hash_t *pid_bpf_links, *tmp;
    struct bpf_program *prog;
    struct svg_stack_trace_s *svg_st = arg;
    const char *elf_path;
    char func_sec[BPF_FUNC_NAME_LEN] = {0};
    bool is_uretprobe;
    u64 symbol_offset;
    // Read raw stack-trace data from current data channel.
    while (!g_stop) {
        sleep(g_ipc_body.probe_param.period);

        set_pids_inactive();
        if (add_pids() != 0) {
            continue;
        }
        H_ITER(bpf_link_head, pid_bpf_links, tmp) { // for pids
            i = 0;
            if (pid_bpf_links->v.pid_state == PID_ELF_TOBE_ATTACHED) {
                bpf_object__for_each_program(prog, svg_st->obj) { // for bpf progs
                    is_uretprobe = get_bpf_prog(prog, func_sec, BPF_FUNC_NAME_LEN);
                    elf_path = (const char *)pid_bpf_links->v.elf_path;
                    err = gopher_get_elf_symb(elf_path, func_sec, &symbol_offset);
                    if (err < 0) {
                        ERROR("[STACKPROBE]: Failed to get func(%s) in(%s) offset.\n", func_sec, elf_path);
                        break;
                    }
                    pid_bpf_links->v.bpf_links[i] = bpf_program__attach_uprobe(prog, is_uretprobe, -1,
                        elf_path, (size_t)symbol_offset);

                    err = libbpf_get_error(pid_bpf_links->v.bpf_links[i]); 
                    if (err) {
                        ERROR("[STACKPROBE]: attach mem bpf to pid %u failed %d\n", pid_bpf_links->pid, err);
                        break;
                    }
                    i++;
                }
                if (err == 0) {
                    pid_bpf_links->v.pid_state = PID_ELF_ATTACHED;
                    pid_bpf_links->v.bpf_link_num = i;
                    INFO("[STACKPROBE]: attach mem bpf to pid %u success\n", pid_bpf_links->pid);
                } else {
                    pid_bpf_links->v.bpf_links[i] = NULL;
                    for (i--; i >= 0; i--) {
                        bpf_link__destroy(pid_bpf_links->v.bpf_links[i]);
                    }
                }
            }
        }
        clear_invalid_pids();
    }

    unload_bpf_progs(svg_st);

    return NULL;

}
#endif
static int attach_mem_bpf_prog(struct ipc_body_s *ipc_body, struct svg_stack_trace_s *svg_st)
{
    int err;
#if 1
    // this is for mem.bpf.c and mem_fp.bpf.c
    int i = 0;
    struct bpf_program *prog;
    struct bpf_link *links[MEM_SEC_NUM] = {0};

    bpf_object__for_each_program(prog, svg_st->obj) {
        links[i] = bpf_program__attach(prog);
        err = libbpf_get_error(links[i]); 
        if (err) {
            ERROR("[STACKPROBE]: attach mem bpf failed %d\n", err);
            links[i] = NULL;
            goto cleanup;
        }
        i++;
    }

    INFO("[STACKPROBE]: attach mem bpf succeed.\n");
    return 0;
cleanup:
    for (i--; i >= 0; i--) {
        bpf_link__destroy(links[i]);
    }

    return -1;
#else
    // this is for mem_glibc.bpf.c
    pthread_t uprobe_attach_thd;

    err = pthread_create(&uprobe_attach_thd, NULL, __uprobe_attach_check, (void *)svg_st);
    if (err != 0) {
        ERROR("[STACKPROBE]: attach mem bpf failed %d\n", err);
        return -1;
    }
    (void)pthread_detach(uprobe_attach_thd);

    INFO("[STACKPROBE]: attach mem bpf succeed.\n");
    return 0;
#endif
}

static void clear_stackmap(int stackmap_fd)
{
    u32 stackid = 0, next_id;
    while (bpf_map_get_next_key(stackmap_fd, &stackid, &next_id) == 0) {
        bpf_map_delete_elem(stackmap_fd, &next_id);
        stackid = next_id;
    }
}

static void clear_running_ctx(struct stack_trace_s *st)
{
    u64 pcache_crt, pcache_del;
    clear_stackmap(get_stack_map_fd(st));
    for (int i = 0; i < STACK_SVG_MAX; i++) {
        if (st->svg_stack_traces[i] == NULL) {
            continue;
        }
        clear_stack_histo(st->svg_stack_traces[i]);
    }

    pcache_del = st->stats.count[STACK_STATS_PCACHE_DEL];
    pcache_crt = st->stats.count[STACK_STATS_PCACHE_CRT];
    (void)memset(&(st->stats), 0, sizeof(st->stats));
    st->stats.count[STACK_STATS_PCACHE_DEL] = pcache_del;
    st->stats.count[STACK_STATS_PCACHE_CRT] = pcache_crt;
}

static void record_running_ctx(struct stack_trace_s *st)
{
#if 1 //GOPHER_DEBUG
    int i, len, ret;
    char *pos;
    char buf[LINE_BUF_LEN];

    const char *col[STACK_STATS_MAX] = {"RAW", "LOSS", "HISTO_ERR", "HISTO_FOLD", "ID2SYMBS",
        "PCACHE_DEL", "PCACHE_CRT", "KERN_ERR", "USER_ERR", "MAP_LKUP_ERR",
        "KERN_OK", "USER_OK", "KERN_USER", "P_CACHE", "SYMB_CACHE"};
    const int offset[STACK_STATS_MAX] = {-8, -8, -10, -12, -10, -12, -12, -10, -10, -14, -9, -9, -11, -9, 12};

    printf("\n========================================================================================\n");

    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;
    for (i = 0; i < STACK_STATS_MAX - 1; i++) {
        ret = snprintf(pos, len, "%*s", offset[i], col[i]);
        len -= ret;
        pos += ret;
    }
    (void)snprintf(pos, len, "%*s\n", offset[i], col[i]);

    printf(buf);

    buf[0] = 0;
    pos = buf;
    len = LINE_BUF_LEN;
    for (i = 0; i < STACK_STATS_MAX - 1; i++) {
        ret = snprintf(pos, len, "%*llu", offset[i], st->stats.count[i]);
        len -= ret;
        pos += ret;
    }
    (void)snprintf(pos, len, "%*llu\n", offset[i], st->stats.count[i]);
    printf(buf);
#endif
    return;
}

static void *__running(void *arg)
{
    int ret;
    struct svg_stack_trace_s *svg_st = arg;
    struct perf_buffer *pb = get_pb(g_st, svg_st);

    // Read raw stack-trace data from current data channel.
    while ((pb != NULL) && (ret = perf_buffer__poll(pb, 0)) >= 0) {
        if (g_stop) {
            break;
        }
        pb = get_pb(g_st, svg_st);
        sleep(1);
    }
    return NULL;
}

static FILE *__get_flame_graph_fp(struct stack_svg_mng_s *svg_mng)
{
    struct stack_flamegraph_s *sfg;

    sfg = &(svg_mng->flame_graph);
    return sfg->fp;
}

int  __do_wr_stack_histo(struct stack_svg_mng_s *svg_mng, struct stack_trace_histo_s *stack_trace_histo,
    struct post_info_s *post_info)
{
    FILE *fp = __get_flame_graph_fp(svg_mng);
    if (!fp) {
        ERROR("[STACKPROBE]: Invalid fp.\n");
        return -1;
    }

    __histo_tmp_str[0] = 0;
    (void)snprintf(__histo_tmp_str, HISTO_TMP_LEN, "%s %llu\n",
                stack_trace_histo->stack_symbs_str, stack_trace_histo->count);

    if (post_info->post_flag) {
        int written = post_info->buf - post_info->buf_start;
        int ret = __snprintf(&post_info->buf, post_info->remain_size, &post_info->remain_size, "%s", __histo_tmp_str);
        if (ret < 0) {
            int new_post_max = g_post_max + POST_MAX_STEP_SIZE;
            char *temp = (char *)realloc(post_info->buf_start, new_post_max);
            if(temp == NULL) {
                ERROR("[STACKPROBE]: Not enough post memory (realloc failed), current capacity is %d.\n",
                    g_post_max);
            } else {
                post_info->buf_start = temp;
                post_info->buf = post_info->buf_start + written;
                post_info->remain_size += POST_MAX_STEP_SIZE;
                g_post_max = new_post_max;
                INFO("[STACKPROBE]: post memory realloc to %d\n", g_post_max);
                (void)__snprintf(&post_info->buf, post_info->remain_size, &post_info->remain_size, "%s", __histo_tmp_str);
            }
        }
    }

    (void)fputs(__histo_tmp_str, fp);
    return 0;
}

void iter_histo_tbl(struct proc_stack_trace_histo_s *proc_histo, struct post_server_s *post_server,
    struct stack_svg_mng_s *svg_mng, int en_type)
{
    struct stack_trace_histo_s *item, *tmp;
    struct post_info_s post_info = {.remain_size = g_post_max, .post_flag = 0};

    init_curl_handle(post_server, &post_info);

    H_ITER(proc_histo->histo_tbl, item, tmp) {
        (void)__do_wr_stack_histo(svg_mng, item, &post_info);
    }

    if (post_info.post_flag) {
        curl_post(post_server, &post_info, en_type, proc_histo->proc_id);
    }

    return;
}

static int set_jstack_args(struct java_attach_args *attach_args)
{
    int len = ATTACH_TYPE_LEN;
    int ret;
    char *pos = attach_args->action; // eg: oncpu|offcpu|mem|,10
    char *flame_types[] = {"oncpu", "offcpu", "mem", "io"};
    u32 perf_sample_period = g_st->post_server.perf_sample_period;
    attach_args->action[0] = 0;
    for (int i = 0; i < STACK_SVG_MAX; i++) {
        if (g_st->svg_stack_traces[i] != NULL) {
            ret = __snprintf(&pos,(const int)len, &len, "%s|", flame_types[i]);
            if (ret < 0) {
                return ret;
            }
        }
    }
    ret = __snprintf(&pos,(const int)len, &len, ",%u", perf_sample_period);
    if (ret < 0) {
        return ret;
    }
    (void)snprintf(attach_args->agent_file_name, FILENAME_LEN, "%s", JSTACK_AGENT_FILE); 
    return 0;
}

static void add_java_proc_histo_item(unsigned int pid)
{
    struct proc_stack_trace_histo_s *proc_histo;
    for (int i = 0; i < STACK_SVG_MAX; i++) {
        if (g_st->svg_stack_traces[i] != NULL) {
            proc_histo = get_proc_histo_item(g_st->svg_stack_traces[i], pid);
            if (proc_histo == NULL) {
                (void)add_proc_histo_item(g_st->svg_stack_traces[i], pid, PROC_STACK_STORE_IN_FILE);
            } else {
                proc_histo->proc_stack_type = PROC_STACK_STORE_IN_FILE;
            }
        }
    }
}

// load cmd example: 
// jvm_attach 123456 1 load instrument false "/tmp/JstackProbeAgent.jar=123456,/tmp/java-data-123456,oncpu|offcpu|mem|,10"
static void load_jstack_agent()
{
    if (!g_st || (g_st->proc_obj_map_fd <= 0)) {
        ERROR("[STACKPROBE]: Load jvm agent failed!\n");
        return;
    }

    int ret = 0;
    unsigned int pid;
    int proc_obj_map_fd = g_st->proc_obj_map_fd;
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s value = {0};
    struct java_attach_args attach_args = {0};
    char comm[TASK_COMM_LEN];

    if (set_jstack_args(&attach_args)) {
        return;
    }

    while (bpf_map_get_next_key(proc_obj_map_fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(proc_obj_map_fd, &next_key, &value);
        key = next_key;
        if (ret < 0) {
            continue;
        }
        pid = key.proc_id;
        comm[0] = 0;
        ret = detect_proc_is_java(pid, comm, TASK_COMM_LEN);
        if (ret == 0) {
            continue;
        }
        ret = java_load(pid, (void *)&attach_args);
        if (ret == 0) {
            add_java_proc_histo_item(pid);
            INFO("[STACKPROBE]: Attach to proc %d succeed\n", pid);
        }
    }
}

static void switch_stackmap()
{
    struct stack_trace_s *st = g_st;
    if (st == NULL) {
        return;
    }
    st->is_stackmap_a = ((st->convert_stack_count % 2) == 0);

    if (!is_tmout(st)) { // 30s
        return;
    }

    // Notify BPF to switch to another channel
    st->convert_stack_count++;
    update_convert_counter();

    /* 
     *  The jstack agent walks call stack based on JFR, which is different from the perf-event-based stack walker for
     *  native language process. Therefore when the jstack agent is used to walk call stack, the flame graphs of
     *  different processes cannot be merged, meanwhile, the call stack of the JVM itself (that is, the local language
     *  stack part of the process) cannot be obtained.
     */
    if (st->multi_instance_flag && !st->native_stack_flag) {
        load_jstack_agent();
    }

    // Histogram format to flame graph
    for (int i = 0; i < STACK_SVG_MAX; i++) {
        if (st->svg_stack_traces[i] == NULL) {
            continue;
        }
        if (stack_id2histogram(st, i, st->is_stackmap_a) != 0) {
            continue;
        }
        if (H_COUNT(st->svg_stack_traces[i]->proc_histo_tbl) != 0) {
            wr_flamegraph(&st->svg_stack_traces[i]->proc_histo_tbl, st->svg_stack_traces[i]->svg_mng, i, &st->post_server);
        }
        clear_raw_stack_trace(st->svg_stack_traces[i], st->is_stackmap_a);
    }
    record_running_ctx(st);
    // Clear the context information of the running environment.
    clear_running_ctx(st);
    sleep(1);
}

static void init_wr_flame_pthreads(struct svg_stack_trace_s *svg_st, const char *flame_name)
{
    int err;
    pthread_t wr_flame_thd;

    err = pthread_create(&wr_flame_thd, NULL, __running, (void *)svg_st);
    if (err != 0) {
        ERROR("[STACKPROBE]: Failed to create %s wr_flame_pthread.\n", flame_name);
        g_stop = 1;
        return;
    }
    svg_st->wr_flame_thd = wr_flame_thd;
    (void)pthread_detach(wr_flame_thd);
    INFO("[STACKPROBE]: %s wr_flame_pthread successfully started!\n", flame_name);

    return;
}

static int init_enabled_svg_stack_traces(struct ipc_body_s *ipc_body)
{
    struct svg_stack_trace_s *svg_st;

    FlameProc flameProcs[] = {
        // This array order must be the same as the order of enum stack_svg_type_e
        { PROBE_RANGE_ONCPU, STACK_SVG_ONCPU, "oncpu", ON_CPU_PROG, attach_oncpu_bpf_prog, process_oncpu_raw_stack_trace},
        { PROBE_RANGE_OFFCPU, STACK_SVG_OFFCPU, "offcpu", OFF_CPU_PROG, attach_offcpu_bpf_prog, process_offcpu_raw_stack_trace},
        { PROBE_RANGE_MEM, STACK_SVG_MEM, "mem", MEM_PROG, attach_mem_bpf_prog, process_mem_raw_stack_trace},
        { PROBE_RANGE_IO, STACK_SVG_IO, "io", IO_PROG, NULL, NULL},
    };
    
    for (int i = 0; i < STACK_SVG_MAX; i++) {
        if (!IS_LOAD_PROBE(ipc_body->probe_range_flags, flameProcs[i].sw)) {
            continue;
        }

        svg_st = create_svg_stack_trace(ipc_body, flameProcs[i].flame_name);
        if (!svg_st) {
            return -1;
        }
        g_st->svg_stack_traces[i] = svg_st;

        if (load_bpf_prog(svg_st, flameProcs[i].prog_name)) {
            return -1;
        }

        if (create_perf(svg_st, flameProcs[i].cb)) {
            return -1;
        }

        if (flameProcs[i].func) {
            if (flameProcs[i].func(ipc_body, svg_st)) {
                return -1;
            }
        }

        // Initializing the BPF Data Channel
        init_wr_flame_pthreads(svg_st, flameProcs[i].flame_name);
    }
    return 0;
}

// load cmd example: 
// jvm_attach 123456 1 load /tmp/jvm_agent.so true /tmp/java-data-123456
static void load_jvm_agent()
{
    if (!g_st || (g_st->proc_obj_map_fd <= 0)) {
        ERROR("[STACKPROBE]: Load jvm agent failed!\n");
        return;
    }

    int ret = 0;
    unsigned int pid;
    int proc_obj_map_fd = g_st->proc_obj_map_fd;
    struct proc_s key = {0};
    struct proc_s next_key = {0};
    struct obj_ref_s value = {0};
    struct java_attach_args attach_args = {0};
    char comm[TASK_COMM_LEN];
    (void)snprintf(attach_args.agent_file_name, FILENAME_LEN, "%s", JAVA_SYM_AGENT_FILE);
    while (bpf_map_get_next_key(proc_obj_map_fd, &key, &next_key) == 0) {
        ret = bpf_map_lookup_elem(proc_obj_map_fd, &next_key, &value);
        key = next_key;
        if (ret < 0) {
            continue;
        }
        pid = key.proc_id;
        comm[0] = 0;
        ret = detect_proc_is_java(pid, comm, TASK_COMM_LEN);
        if (ret == 0) {
            continue;
        }

        ret = java_load(pid, (void *)&attach_args);
        if (ret == 0) {
            INFO("[STACKPROBE]: Attach to proc %d succeed\n", pid);
        }
    }
}

static void reload_observation_range(struct ipc_body_s *ipc_body)
{
    if (ipc_body == NULL) {
        ERROR("[STACKPROBE]: ipc body is NULL when reload observation ranges\n");
        return;
    }

    if (ipc_body->probe_flags & IPC_FLAGS_SNOOPER_CHG || ipc_body->probe_flags == 0) {
        unload_stackprobe_snoopers();
        load_stackprobe_snoopers(ipc_body);
        init_convert_counter();
    }

    if (ipc_body->probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body->probe_flags == 0) {
        if (!g_st->multi_instance_flag || g_st->native_stack_flag) {
            load_jvm_agent();
        }
    }
}

static int reload_probe_params(struct ipc_body_s *ipc_body)
{
    int err;

    if (ipc_body == NULL) {
        ERROR("[STACKPROBE]: ipc body is NULL when reload probe params\n");
        return -1;
    }

    if (ipc_body->probe_flags & IPC_FLAGS_PARAMS_CHG || ipc_body->probe_flags == 0) {
        if (g_st != NULL) {
            destroy_stack_trace(&g_st);
        }
        g_st = create_stack_trace(ipc_body);
        if (!g_st) {
            ERROR("[STACKPROBE]: can't create stack trace\n");
            return -1;
        }
        err = init_enabled_svg_stack_traces(ipc_body);
        if (err != 0) {
            ERROR("[STACKPROBE]: can't create svg stack trace\n");
            return -1;
        }

        INFO("[STACKPROBE]: Successfully started from new parameters!\n");
    }

    return 0;
}

#ifdef EBPF_RLIM_LIMITED
#undef EBPF_RLIM_LIMITED
#endif
#define EBPF_RLIM_LIMITED  500*1024*1024 // 500M
int main(int argc, char **argv)
{
    int err = -1;
    struct ipc_body_s ipc_body;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        ERROR("[STACKPROBE]: can't set signal handler: %d\n", errno);
        return errno;
    }

    FILE *fp = popen(RM_STACK_PATH, "r");
    if (fp != NULL) {
        (void)pclose(fp);
        fp = NULL;
    }

    (void)memset(&g_ipc_body, 0, sizeof(g_ipc_body));

    int msq_id = create_ipc_msg_queue(IPC_EXCL);
    if (msq_id < 0) {
        ERROR("[STACKPROBE]: can't create ipc msg_queue: %d\n", errno);
        goto out;
    }

    INIT_BPF_APP(stackprobe, EBPF_RLIM_LIMITED);
    INFO("[STACKPROBE]: Started successfully.\n");

    while (!g_stop) {
        err = recv_ipc_msg(msq_id, (long)PROBE_FG, &ipc_body);
        if (err == 0) {
            INFO("[STACKPROBE]: recv new ipc\n");
            if (reload_probe_params(&ipc_body) != 0) {
                goto out;
            }
            reload_observation_range(&ipc_body);
            destroy_ipc_body(&g_ipc_body);
            (void)memcpy(&g_ipc_body, &ipc_body, sizeof(g_ipc_body));
        }

        switch_stackmap();
        sleep(1);
    }

out:
    g_stop = 1;
    if (g_st != NULL) {
        destroy_stack_trace(&g_st);
    }
    destroy_ipc_body(&g_ipc_body);

    return -err;
}
