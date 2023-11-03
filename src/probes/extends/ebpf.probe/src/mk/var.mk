ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

Q = @

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(ROOT_DIR)/../../tools/bpftool
TOOL_DIR ?= $(ROOT_DIR)/../../tools
VMLINUX ?= $(ROOT_DIR)/../include/vmlinux.h
INCLUDE_DIR ?= $(ROOT_DIR)/../include
LIBBPF_DIR = $(ROOT_DIR)/../.output
LIBELF_DIR = /usr/include/libelf
GOPHER_COMMON_DIR = $(ROOT_DIR)/../../../../../common

LIB_DIR ?= $(ROOT_DIR)../lib
CFILES ?= $(wildcard $(LIB_DIR)/*.c)
CFILES += $(wildcard $(GOPHER_COMMON_DIR)/*.c)

CPLUSFILES += $(wildcard $(GOPHER_COMMON_DIR)/*.cpp)

INSTALL_DIR=/usr/bin/extends/ebpf.probe

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

ifeq ($(wildcard $(VMLINUX)), )
    $(shell cd $(INCLUDE_DIR); \
    ln -s linux_${LINUX_VER}.h vmlinux.h;)
endif

LIBBPF_VER = $(shell rpm -q libbpf | awk -F'-' '{print $$2}')
LIBBPF_VER_MAJOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$1}')
LIBBPF_VER_MINOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$2}')

ifeq ($(wildcard $(BPFTOOL)), )
    $(shell cd $(TOOL_DIR); \
    if [ $(LIBBPF_VER_MAJOR) -gt 0 ]; then ln -s bpftool_v6.8.0/bpftool_${ARCH} bpftool; \
    elif [ $(LIBBPF_VER_MINOR) -ge 8 ]; then ln -s bpftool_v6.8.0/bpftool_${ARCH} bpftool; \
    else ln -s bpftool_${ARCH} bpftool; fi; )
endif

BTF_ENABLE = $(shell if [ -f /sys/kernel/btf/vmlinux ]; then echo "ON" ; else echo "OFF"; fi)

LINK_TARGET ?= -lpthread -lbpf -lelf -llog4cplus -lz -lconfig -ljsoncpp
EXTRA_CFLAGS ?= -g -O2 -Wall -fPIC -std=gnu11
EXTRA_CDEFINE ?= -D__TARGET_ARCH_$(TYPE)
EXTRA_CDEFINE += -D__BTF_ENABLE_$(BTF_ENABLE)
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -DKER_VER_MAJOR=$(KER_VER_MAJOR) -DKER_VER_MINOR=$(KER_VER_MINOR) -DKER_VER_PATCH=$(KER_VER_PATCH)
CFLAGS += -DKER_RELEASE=$(KER_RELEASE)
CFLAGS += -DLIBBPF_VER_MAJOR=$(LIBBPF_VER_MAJOR) -DLIBBPF_VER_MINOR=$(LIBBPF_VER_MINOR)
LDFLAGS += -Wl,--copy-dt-needed-entries -Wl,-z,relro,-z,now

CXXFLAGS += -std=c++11 -g -O2 -Wall -fPIC
C++ = g++
CC = gcc

CLANGFLAGS := $(CFLAGS)
CFLAGS += -Wno-format-truncation

BASE_INC := -I/usr/include \
            -I$(ROOT_DIR)../include \
            -I$(GOPHER_COMMON_DIR) \
            -I$(LIBBPF_DIR) \
            -I$(LIBELF_DIR)
