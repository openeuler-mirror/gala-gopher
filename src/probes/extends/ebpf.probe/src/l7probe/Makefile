# force BPF programs to use CO-RE helpers regardless of whether kernel BTF is
# present in the build environment
BTF_ENABLE_OVERRIDE := ON

include ../mk/var.mk
INCLUDES = $(BASE_INC)
INCLUDES += -I$(ROOT_DIR)/../l7probe
INCLUDES += -I$(ROOT_DIR)/../l7probe/3rd_party/pico
INSTALL_DIR=/opt/gala-gopher/extend_probes
APP := l7probe
SRC_CPLUS := $(wildcard *.cpp)
SRC_CPLUS += $(CPLUSFILES)

OBJ_BTF := min_core_btfs.o
TAR_BTF := min_core_btfs.tar.gz
BPF_C := $(wildcard bpf/*.bpf.c)
BPF_PROG := $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
DEPS := $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
DEPS += $(patsubst %.bpf.c, %.skel.h, $(BPF_C))
DEPS += $(patsubst %.cpp, %.o, $(SRC_CPLUS))
DEPS += $(OBJ_BTF) $(TAR_BTF)

SRC_C := $(filter-out $(BPF_C), $(wildcard *.c))
PROTOCOL_DIR = $(shell find ./protocol -maxdepth 3 -type d)
SRC_C += $(foreach dir, $(PROTOCOL_DIR), $(wildcard $(dir)/*.c))
SRC_C += $(CFILES)
SRC_C += $(wildcard $(ROOT_DIR)/../l7probe/3rd_party/pico/*.c)

.PHONY: all clean install

all: pre deps app
pre: $(OUTPUT)
deps: $(DEPS)
# build bpf code
%.bpf.o: %.bpf.c
	$(CLANG) $(CLANGFLAGS) -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

# build skel.h
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# build c++ files
%.o: %.cpp
	$(C++) -c $^ $(CXXFLAGS) $(INCLUDES) -o $@

# build stripped BTFs
$(TAR_BTF): $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
	BTFHUB_CACHE=$(BTFHUB_CACHE) \
	BTFHUB_REPO=$(BTFHUB_REPO) \
	$(BTFGEN) btfgen -o $@ $^

$(OBJ_BTF): $(TAR_BTF)
	$(LD) -r -b binary -o $@ -b binary $<

app: $(APP)
%: %.c $(SRC_C) $(OBJ_BTF)
	$(CC) $(CFLAGS) $(patsubst %.cpp, %.o, $(SRC_CPLUS))  $(INCLUDES) $^ $(LDFLAGS) $(LINK_TARGET) -o $@
	@echo $@ "compiling completed."

clean:
	rm -rf $(DEPS)
	rm -rf $(APP)

install:
	mkdir -p $(INSTALL_DIR)/l7_bpf
	cp $(APP) $(INSTALL_DIR)
	cp $(BPF_PROG) $(INSTALL_DIR)/l7_bpf
