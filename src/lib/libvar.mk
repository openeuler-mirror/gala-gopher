ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

Q = @

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(ROOT_DIR)/../probes/extends/ebpf.probe/tools/bpftool
TOOL_DIR ?= $(ROOT_DIR)/../probes/extends/ebpf.probe/tools
VMLINUX ?= $(ROOT_DIR)/../probes/extends/ebpf.probe/src/include/vmlinux.h
LIBBPF_DIR = $(ROOT_DIR)/.output
LIBELF_DIR = /usr/include/libelf
VMLINUX_DIR ?= $(ROOT_DIR)/../probes/extends/ebpf.probe/src/include

ARCH = $(shell uname -m)
ifeq ($(ARCH), x86_64)
    TYPE = x86
else ifeq ($(ARCH), aarch64)
    TYPE = arm64
endif

LINUX_VER = $(shell [ -n "$(VMLINUX_VER)" ] && echo $(VMLINUX_VER) || uname -r)
KER_VER = $(shell echo $(LINUX_VER) | awk -F'-' '{print $$1}')
KER_VER_MAJOR = $(shell echo $(KER_VER) | awk -F'.' '{print $$1}')
KER_VER_MINOR = $(shell echo $(KER_VER) | awk -F'.' '{print $$2}')
KER_VER_PATCH = $(shell echo $(KER_VER) | awk -F'.' '{print $$3}')
RELEASE_INFOS = $(shell echo $(LINUX_VER) | awk -F'-' '{print $$2}')
KER_RELEASE = $(shell echo $(RELEASE_INFOS) | awk -F'.' '{print $$1}')

LIBBPF_VER = $(shell rpm -q libbpf | awk -F'-' '{print $$2}')
LIBBPF_VER_MAJOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$1}')
LIBBPF_VER_MINOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$2}')

BTF_ENABLE = $(shell if [ -f /sys/kernel/btf/vmlinux ]; then echo "ON" ; else echo "OFF"; fi)

EXTRA_CFLAGS ?= -g -O2 -Wall -fPIC -std=gnu11
EXTRA_CDEFINE ?= -D__TARGET_ARCH_$(TYPE)
EXTRA_CDEFINE += -D__BTF_ENABLE_$(BTF_ENABLE)
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -DKER_VER_MAJOR=$(KER_VER_MAJOR) -DKER_VER_MINOR=$(KER_VER_MINOR) -DKER_VER_PATCH=$(KER_VER_PATCH)
CFLAGS += -DKER_RELEASE=$(KER_RELEASE)
CFLAGS += -DLIBBPF_VER_MAJOR=$(LIBBPF_VER_MAJOR) -DLIBBPF_VER_MINOR=$(LIBBPF_VER_MINOR)

BASE_INC := -I/usr/include \
            -I$(ROOT_DIR)/../common \
            -I$(ROOT_DIR)/lib \
            -I$(VMLINUX_DIR) \
            -I$(LIBBPF_DIR) \
            -I$(LIBELF_DIR)
