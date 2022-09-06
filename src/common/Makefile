ARCH = $(shell uname -m)
ifeq ($(ARCH), x86_64)
	ARCH = x86
else ifeq ($(ARCH), aarch64)
	ARCH = arm64
endif

LINK_TARGET := -lpthread -lbpf -lelf -lz
EXTRA_CFLAGS := -g -O2 -Wall -fPIC -shared
EXTRA_CDEFINE := -D__TARGET_ARCH_$(ARCH)
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)

INCLUDES := -I/usr/include

SRC_C := util.c object.c
DEPS := object.h
OUTPUT_LIBS := object.so

.PHONY: out clean

out: $(SRC_C) $(DEPS)
	$(CC) $(CFLAGS) $(INCLUDES) $^ $(LINK_TARGET)  -o $(OUTPUT_LIBS)

clean:
	rm -rf $(OUTPUT_LIBS)

