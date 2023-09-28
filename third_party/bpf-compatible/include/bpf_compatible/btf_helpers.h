#ifndef _BTF_HELPER_H
#define _BTF_HELPER_H

#include <bpf/libbpf.h>

int ensure_core_btf_with_tar_binary(const char** path,
                                    const char* tar_bin,
                                    int tar_len);

int ensure_core_btf_with_linked_tar(const char** path);

void clean_core_btf_rs(const char* path);

static int ensure_core_btf(struct bpf_object_open_opts* opts) {
    return ensure_core_btf_with_linked_tar(&opts->btf_custom_path);
}

static int ensure_core_btf_tar(struct bpf_object_open_opts* opts,
                               const char* tar_bin,
                               int tar_len) {
    return ensure_core_btf_with_tar_binary(&opts->btf_custom_path, tar_bin,
                                           tar_len);
}

static void cleanup_core_btf(struct bpf_object_open_opts* opts) {
    clean_core_btf_rs(opts->btf_custom_path);
}

// Allow for not linking the tar binary
char _binary_min_core_btfs_tar_gz_start __attribute__((weak));
char _binary_min_core_btfs_tar_gz_end __attribute__((weak));

#endif  // _BTF_HELPER_H
