include ../libvar.mk
INCLUDES = $(BASE_INC)

BPF_C := $(wildcard *.bpf.c)
DEPS := $(patsubst %.bpf.c, %.skel.h, $(BPF_C))

.PHONY: all clean
all: build

build: $(DEPS)

# build bpf code
%.bpf.o: %.bpf.c
	$(CLANG) $(CLANGFLAGS) -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

# build skel.h
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	rm -rf *.bpf.o
	rm -rf *.skel.h
