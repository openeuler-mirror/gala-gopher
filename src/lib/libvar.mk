ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

Q = @

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
VMLINUX ?= $(ROOT_DIR)/../probes/extends/ebpf.probe/src/include/vmlinux.h
LIBBPF_DIR = $(ROOT_DIR)/.output
LIBELF_DIR = /usr/include/libelf
VMLINUX_DIR ?= $(ROOT_DIR)/../probes/extends/ebpf.probe/src/include

ARCH = $(shell uname -m)
ifeq ($(ARCH), x86_64)
    TYPE = x86
else ifeq ($(ARCH), aarch64)
    TYPE = arm64
else ifeq ($(ARCH), riscv64)
    TYPE = riscv
endif

LIBBPF_VER = $(shell rpm -q libbpf | awk -F'-' '{print $$2}')
LIBBPF_VER_MAJOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$1}')
LIBBPF_VER_MINOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$2}')

CLANG_VER = $(shell clang --version | head -n 1 | awk -F ' ' '{print $$3}')
CLANG_VER_MAJOR = $(shell echo $(CLANG_VER) | awk -F '.' '{print $$1}')

BTF_ENABLE = $(shell if [ -f /sys/kernel/btf/vmlinux ]; then echo "ON" ; else echo "OFF"; fi)

EXTRA_CFLAGS ?= -g -O2 -Wall -fPIC -std=gnu11
EXTRA_CDEFINE ?= -D__TARGET_ARCH_$(TYPE)
EXTRA_CDEFINE += -D__BTF_ENABLE_$(BTF_ENABLE)
EXTRA_CDEFINE += -DBPF_NO_GLOBAL_DATA
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -DLIBBPF_VER_MAJOR=$(LIBBPF_VER_MAJOR) -DLIBBPF_VER_MINOR=$(LIBBPF_VER_MINOR) -DCLANG_VER_MAJOR=$(CLANG_VER_MAJOR)
CFLAGS += $(shell [ -n "$(NATIVE_PROBE_OPTS)" ] && echo $(NATIVE_PROBE_OPTS))
CFLAGS += $(shell [ -n "$(EXTEND_PROBE_OPTS)" ] && echo $(EXTEND_PROBE_OPTS))
CFLAGS += $(shell [ -n "$(FEATURE_OPTS)" ] && echo $(FEATURE_OPTS))

CLANGFLAGS := $(CFLAGS)
CFLAGS += -Wno-format-truncation

BASE_INC := -I/usr/include \
            -I$(ROOT_DIR)/../common \
            -I$(ROOT_DIR)/lib \
            -I$(VMLINUX_DIR) \
            -I$(LIBBPF_DIR) \
            -I$(LIBELF_DIR)
