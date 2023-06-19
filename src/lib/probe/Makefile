include ../libvar.mk
INCLUDES = $(BASE_INC)

ifeq ($(wildcard $(BPFTOOL)), )
    $(shell cd $(TOOL_DIR); \
    if [ $(LIBBPF_VER_MAJOR) -gt 0 ]; then ln -s bpftool_v6.8.0/bpftool_${ARCH} bpftool; \
    elif [ $(LIBBPF_VER_MINOR) -ge 8 ]; then ln -s bpftool_v6.8.0/bpftool_${ARCH} bpftool; \
    else ln -s bpftool_${ARCH} bpftool; fi; )
endif

BPF_C := $(wildcard *.bpf.c)
DEPS := $(patsubst %.bpf.c, %.skel.h, $(BPF_C))

.PHONY: all clean
all: build

build: $(DEPS)

# build bpf code
%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

# build skel.h
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -rf *.bpf.o
	rm -rf *.skel.h
