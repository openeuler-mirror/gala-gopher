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
 * Description: elf module
 ******************************************************************************/
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <gelf.h>

#include "gopher_elf.h"

struct elf_symb_s {
    char *symb;
    u64 start_addr;
};

struct elf_header_s {
    u64 p_vaddr;
    u64 p_offset;
    u64 p_memsz;
};

#if 1
static int open_elf_fd(int fd, Elf **elf_bin)
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        return -1;
    }

    *elf_bin = elf_begin(fd, ELF_C_READ, 0);
    if (*elf_bin == NULL) {
        return -1;
    }
    return 0;
}

static int open_elf(const char *elf_file, Elf **elf_bin, int *elf_fd)
{
    *elf_fd = open(elf_file, O_RDONLY);
    if (*elf_fd < 0) {
        goto err;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        goto err;
    }

    *elf_bin = elf_begin(*elf_fd, ELF_C_READ, 0);
    if (*elf_bin == NULL) {
        goto err;
    }

    return 0;
err:
    if (*elf_fd > 0) {
        close(*elf_fd);
    }
    *elf_fd = -1;
    return -1;
}

static int gopher_iter_section_symb(Elf *e, Elf_Scn *sec,
                Elf32_Word another_sec, size_t entry_size, elf_sym_cb cb, void *ctx)
{
    ELF_CB_RET ret;
    size_t sym_count;
    char *name;
    GElf_Sym sym;
    Elf_Data *data = NULL;

    if (entry_size == 0) {
        return -1;
    }

    while ((data = elf_getdata(sec, data)) != NULL) {
        sym_count = data->d_size / entry_size;

        if (data->d_size % entry_size) {
            return -1;
        }

        for (int i = 0; i < sym_count; i++) {

            if (!gelf_getsym(data, i, &sym)) {
                continue;
            }

            if ((name = elf_strptr(e, another_sec, sym.st_name)) == NULL) {
                continue;
            }
            if (name[0] == 0) {
                continue;
            }

            if (sym.st_value == 0) {
                continue;
            }

            if ((ret = cb(name, sym.st_value, sym.st_size, ctx)) && ret != ELF_SYMB_CB_OK) {
                if (ret > 0) {
                    return 0;
                }
                return (int)ret;
            }
        }
    }

    return 0;
}

static int gopher_iter_elf_symb(Elf *e, elf_sym_cb cb, void *ctx)
{
    int ret = 0;
    Elf_Scn *sec = NULL;

    while ((sec = elf_nextscn(e, sec)) != 0) {
        GElf_Shdr header;

        if (!gelf_getshdr(sec, &header)) {
            continue;
        }

        if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM) {
            continue;
        }

        if (gopher_iter_section_symb(e, sec, header.sh_link, header.sh_entsize, cb, ctx)) {
            ret = -1;
            break;
        }
    }

    return ret;
}

static Elf_Scn* gopher_get_elf_section(Elf *e, const char* sec_name)
{
    int ret = -1;
    size_t index;
    Elf_Scn *sec = NULL;
    GElf_Shdr header;
    char *name;

    if ((ret = elf_getshdrstrndx(e, &index)) && ret < 0) {
        goto err;
    }

    while ((sec = elf_nextscn(e, sec)) != 0) {
        if (!gelf_getshdr(sec, &header)) {
            continue;
        }

        name = elf_strptr(e, index, header.sh_name);
        if (name && !strcmp(name, sec_name)) {
            return sec;
        }
    }

err:
    return NULL;
}

static Elf_Data* gopher_get_elf_section_data(Elf *e, const char* sec_name)
{
    Elf_Scn *section = gopher_get_elf_section(e, sec_name);
    if (!section) {
        return NULL;
    }

    return elf_getdata(section, NULL);
}

static int gopher_get_elf_hdr_info(const char *elf_file, struct elf_header_s *hdr)
{
    size_t hdr_num = 0;
    GElf_Phdr header;
    int ret = 0, elf_fd = -1;
    Elf *e = NULL;

    if (open_elf(elf_file, &e, &elf_fd)) {
        ret = -1;
        goto err;
    }

    if (elf_getphdrnum(e, &hdr_num) != 0) {
        goto err;
    }

    for (int i = 0; i < hdr_num; i++) {
        if (!gelf_getphdr(e, i, &header)) {
            continue;
        }

        if (header.p_type != PT_LOAD || !(header.p_flags & PF_X)) {
            continue;
        }

        hdr->p_vaddr  = header.p_vaddr;
        hdr->p_offset = header.p_offset;
        hdr->p_memsz  = header.p_memsz;
        break;
    }

err:
    if (e) {
        elf_end(e);
    }
    if (elf_fd > 0) {
        close(elf_fd);
    }
    return ret;
}

static ELF_CB_RET __search_symbs(const char *symb, u64 addr_start, u64 size, void *ctx)
{
    struct elf_symb_s* target = (struct elf_symb_s *)ctx;
    if (target->symb && !strcmp(symb, target->symb)) {
        target->start_addr = addr_start;
        return ELF_SYMB_CB_BREAK;   // Searched break iter.
    }
    return ELF_SYMB_CB_OK;
}

#endif

int gopher_get_elf_type(const char *elf_file)
{
    Elf *e;
    GElf_Ehdr hdr;
    int fd, elf_type = -1;

    fd = -1;
    e = NULL;
    if (open_elf(elf_file, &e, &fd)) {
        goto err;
    }

    if (gelf_getehdr(e, &hdr) != NULL) {
        elf_type = hdr.e_type;
    }

err:
    elf_end(e);
    close(fd);
    return elf_type;
}

int gopher_get_elf_text_section(const char *elf_file, u64 *addr, u64 *offset)
{
    int ret, fd;
    size_t index;
    Elf *e;
    Elf_Scn *sec = NULL;
    GElf_Shdr header;
    char *name;

    ret = fd = -1;
    e = NULL;
    *addr = *offset = 0;
    if (open_elf(elf_file, &e, &fd)) {
        goto err;
    }

    if ((ret = elf_getshdrstrndx(e, &index)) && ret < 0) {
        goto err;
    }

    while ((sec = elf_nextscn(e, sec)) != 0) {
        if (!gelf_getshdr(sec, &header)) {
            continue;
        }

        name = elf_strptr(e, index, header.sh_name);
        if (name && !strcmp(name, ".text")) {
            *addr = (u64)header.sh_addr;
            *offset = (u64)header.sh_offset;
            ret = 0;
            break;
        }
    }

err:
    if (e) {
        elf_end(e);
    }
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

int gopher_iter_elf_fd_symb(int fd, elf_sym_cb cb, void *ctx)
{
    int ret = 0;
    Elf *e = NULL;

    if (open_elf_fd(fd, &e)) {
        ret = -1;
        goto err;
    }

    if (gopher_iter_elf_symb(e, cb, ctx)) {
        ret = -1;
        goto err;
    }

err:
    if (e) {
        elf_end(e);
    }

    return ret;
}

int gopher_iter_elf_file_symb(const char *elf_file, elf_sym_cb cb, void *ctx)
{
    int ret = 0, elf_fd = -1;
    Elf *e = NULL;

    if (open_elf(elf_file, &e, &elf_fd)) {
        ret = -1;
        goto err;
    }

    if (gopher_iter_elf_symb(e, cb, ctx)) {
        ret = -1;
        goto err;
    }
err:
    if (e) {
        elf_end(e);
    }
    if (elf_fd > 0) {
        close(elf_fd);
    }

    return ret;
}

int gopher_get_elf_symb_addr(const char *elf_file, char *symb_name, u64 *symb_addr)
{
    int ret;
    int elf_type;
    struct elf_symb_s elf_symb = {.symb = symb_name, .start_addr = 0};

    if (elf_file == NULL || symb_name == NULL) {
        return -1;
    }

    elf_type = gopher_get_elf_type(elf_file);
    if (elf_type != ET_DYN && elf_type != ET_EXEC) {
        return -1;
    }

    if ((ret = gopher_iter_elf_file_symb(elf_file, __search_symbs, (void *)&elf_symb)) && ret != 0) {
        return ret;
    }

    if (elf_symb.start_addr == 0) {
        return -1;
    }

    *symb_addr = elf_symb.start_addr;
    return 0;
}

int gopher_get_elf_symb(const char *elf_file, char *symb_name, u64 *symb_offset)
{
    int ret;
    u64 start_addr = 0;
    struct elf_header_s hdr = {0};

    ret = gopher_get_elf_symb_addr(elf_file, symb_name, &start_addr);
    if (ret) {
        return ret;
    }

    if ((ret = gopher_get_elf_hdr_info(elf_file, &hdr)) && ret != 0) {
        return ret;
    }

    // calculate symbol offset : start_addr - hdr.p_vaddr + hdr.p_offset
    if (start_addr >= hdr.p_vaddr && start_addr < (hdr.p_vaddr + hdr.p_memsz)) {
        *symb_offset = start_addr - hdr.p_vaddr + hdr.p_offset;
        return 0;
    }
    return -1;
}

#define __ELF_BUILD_ID_LEN  16
#define __ELF_BUILD_ID_GNU_OFFSET  12
int gopher_get_elf_build_id(const char *elf_file, char build_id[], size_t len)
{
    char *d_buf;
    size_t d_size;
    int ret = 0, elf_fd = -1;
    Elf *e = NULL;

    if (open_elf(elf_file, &e, &elf_fd)) {
        ret = -1;
        goto err;
    }

    Elf_Data *data = gopher_get_elf_section_data(e, ".note.gnu.build-id");
    if (!data || data->d_size <= __ELF_BUILD_ID_LEN || strcmp((char *)data->d_buf + __ELF_BUILD_ID_GNU_OFFSET, "GNU")) {
        ret = -1;
        goto err;
    }

    d_buf = (char *)data->d_buf + __ELF_BUILD_ID_LEN;
    d_size = data->d_size - __ELF_BUILD_ID_LEN;
    for (size_t i = 0; i < d_size; i++) {
        snprintf(build_id + (i * 2), len ,"%02hhx", d_buf[i]);
    }

err:
    if (e) {
        elf_end(e);
    }
    if (elf_fd >= 0) {
        close(elf_fd);
    }
    return ret;
}

#define __ELF_DEBUG_LINK_LEN  5
int gopher_get_elf_debug_link(const char *elf_file, char debug_link[], size_t len)
{
    int ret = 0, elf_fd = -1;
    Elf *e = NULL;
    char *debug_file;

    if (open_elf(elf_file, &e, &elf_fd)) {
        ret = -1;
        goto err;
    }

    Elf_Data *data = gopher_get_elf_section_data(e, ".gnu_debuglink");
    if (!data || data->d_size <= __ELF_DEBUG_LINK_LEN) {
        ret = -1;
        goto err;
    }

    debug_file = (char *)data->d_buf;

    (void)snprintf(debug_link, len, "%s", debug_file);

err:
    if (e) {
        elf_end(e);
    }
    if (elf_fd >= 0) {
        close(elf_fd);
    }
    return ret;
}

#define PYGC_FUNC_NAME_LEN 32
#define MAX_SUPPORT_FUNC_NUM 4
#define MAX_BUILD_VER_NUM 10

struct pygc_offset {
    char func_name[PYGC_FUNC_NAME_LEN];
    u64 offset;
};

struct pygc_build_ver {
    char build_id[ELF_BUILD_ID_LEN];
    int func_num;
    struct pygc_offset func_offsets[MAX_SUPPORT_FUNC_NUM];
};

static struct pygc_build_ver pygc_build_vers[MAX_BUILD_VER_NUM] = {
    {   // libpython3.9.so.1.0-3.9.9-28.oe2203sp1.x86_64.debug
        .build_id = "2570c4d5f065ad4e110e09a65e3366a5f5b87fce",
        .func_num = 1,
        .func_offsets = {
            {"collect_with_callback", 0xb03f0}
        }
    },
    {   // libpython3.9.so.1.0-3.9.9-28.oe2203sp1.aarch64.debug
        .build_id = "36332c2a701cd21ee9b9872870a0091b82f9dfa3",
        .func_num = 1,
        .func_offsets = {
            {"collect_with_callback", 0xb0614}
        }
    }
};
static int pygc_ver_num = 2;

static struct pygc_build_ver* get_build_ver(const char *build_id)
{
    int i;

    for (i = 0; i < pygc_ver_num; i++) {
        if (strcmp(build_id, pygc_build_vers[i].build_id) == 0) {
            return &pygc_build_vers[i];
        }
    }

    return NULL;
}

static u64 get_func_offset(struct pygc_build_ver *build_ver, const char *func_name)
{
    int i;

    for (i = 0; i < build_ver->func_num; i++) {
        if (strcmp(func_name, build_ver->func_offsets[i].func_name) == 0) {
            return build_ver->func_offsets[i].offset;
        }
    }

    return 0;
}

u64 get_func_offset_by_build_id(const char *build_id, const char *func_name)
{
    struct pygc_build_ver *build_ver;

    build_ver = get_build_ver(build_id);
    if (!build_ver) {
        return 0;
    }
    return get_func_offset(build_ver, func_name);
}


