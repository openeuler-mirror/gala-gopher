ARCH = $(shell uname -m)
ifeq ($(ARCH), x86_64)
	ARCH = x86
else ifeq ($(ARCH), aarch64)
	ARCH = arm64
endif

C++ = g++
CC = gcc

LINK_TARGET := -lpthread -lbpf -lelf -lz -llog4cplus
EXTRA_CFLAGS := -g -O2 -Wall -fPIC -shared -Wl,-z,relro,-z,now -std=gnu11
EXTRA_CDEFINE := -D__TARGET_ARCH_$(ARCH)
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CXXFLAGS += -std=c++11 -g -O2 -Wall -fPIC

INCLUDES := -I/usr/include

SRC_C1 := util.c object.c
SRC_C2 := util.c container.c
SRC_CPLUS := logs.cpp

DEPS := $(patsubst %.cpp, %.o, $(SRC_CPLUS))

OUTPUT_LIB1 := object.so
OUTPUT_LIB2 := container.so

all : $(DEPS) $(OUTPUT_LIB1) $(OUTPUT_LIB2)
.PHONY: all clean

$(DEPS): $(SRC_CPLUS)
	$(C++) -c $^ $(CXXFLAGS) $(INCLUDES) -o $@

$(OUTPUT_LIB1): $(SRC_C1)
	$(CC) $(CFLAGS) $(DEPS) $(INCLUDES) $^ $(LINK_TARGET)  -o $@

$(OUTPUT_LIB2): $(SRC_C2) $(DEPS2)
	$(CC) $(CFLAGS) $(DEPS) $(INCLUDES) $^ $(LINK_TARGET)  -o $@

clean:
	rm -rf $(OUTPUT_LIB1) $(OUTPUT_LIB2) $(DEPS)

