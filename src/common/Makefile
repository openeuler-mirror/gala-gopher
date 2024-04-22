ARCH = $(shell uname -m)
ifeq ($(ARCH), x86_64)
	ARCH = x86
else ifeq ($(ARCH), aarch64)
	ARCH = arm64
endif

LIBBPF_VER = $(shell rpm -q libbpf | awk -F'-' '{print $$2}')
LIBBPF_VER_MAJOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$1}')
LIBBPF_VER_MINOR = $(shell echo $(LIBBPF_VER) | awk -F'.' '{print $$2}')

C++ = g++
CC = gcc

LINK_TARGET := -lpthread -lbpf -lelf -lz
EXTRA_CFLAGS := -g -O2 -Wall -fPIC -shared -Wl,-z,relro,-z,now -std=gnu11 -Wno-format-truncation
EXTRA_CDEFINE := -D__TARGET_ARCH_$(ARCH)
EXTRA_CDEFINE += -DBPF_NO_GLOBAL_DATA
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -DLIBBPF_VER_MAJOR=$(LIBBPF_VER_MAJOR) -DLIBBPF_VER_MINOR=$(LIBBPF_VER_MINOR)
CXXFLAGS += -std=c++11 -g -O2 -Wall -fPIC

INCLUDES := -I/usr/include

SRC_C1 := util.c container.c
SRC_C2 := ipc.c

DEPS := logs.o
OUTPUT_LIB1 := container.so
OUTPUT_LIB2 := ipc.so

all : $(DEPS) $(OUTPUT_LIB1) $(OUTPUT_LIB2)
.PHONY: all clean

$(OUTPUT_LIB1): $(SRC_C1)
	$(CC) $(CFLAGS) $(DEPS) $(INCLUDES) $^ $(LINK_TARGET)  -o $@

$(OUTPUT_LIB2): $(SRC_C2)
	$(CC) $(CFLAGS) $(DEPS) $(INCLUDES) $^ $(LINK_TARGET)  -o $@

clean:
	rm -rf $(OUTPUT_LIB1) $(OUTPUT_LIB2) $(OUTPUT_LIB3) $(DEPS)

