# force BPF programs to use CO-RE helpers regardless of whether kernel BTF is
# present in the build environment
BTF_ENABLE_OVERRIDE := ON

include ../mk/var.mk
INCLUDES = $(BASE_INC)

APP := stackprobe
AGENT := jvm_agent.so
SRC_CPLUS := $(wildcard *.cpp)
SRC_CPLUS += $(CPLUSFILES)

OBJ_BTF := min_core_btfs.o
TAR_BTF := min_core_btfs.tar.gz
BPF_C := $(wildcard stack_bpf/*.bpf.c)
BPF_PROG := $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
DEPS = $(BPF_PROG) $(patsubst %.cpp, %.o, $(SRC_CPLUS))
DEPS += $(OBJ_BTF) $(TAR_BTF)

SRC_C := $(wildcard *.c)
SRC_C += $(CFILES)

ALL := pre deps app agent

ifndef JAVA_HOME
	JAVA_HOME := $(abspath $(dir $(realpath $(shell which javac)))/..)
endif
JNI_INC := -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

.PHONY: all clean install

all: $(ALL)
pre: $(OUTPUT)
deps: $(DEPS)
# build bpf code
%.bpf.o: %.bpf.c
	$(CLANG) $(CLANGFLAGS) -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ 

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
	$(CC) $(CFLAGS) $(patsubst %.cpp, %.o, $(SRC_CPLUS)) $(INCLUDES) $^ $(LDFLAGS) $(LINK_TARGET) -lcurl -o $@
	@echo $@ "compiling completed."

agent: $(AGENT)
$(AGENT): jvmti/jvm_agent.c
	$(CC) $(CFLAGS) -shared $(INCLUDES) $(JNI_INC) $^ $(LDFLAGS) -o $@
	@echo $@ "compiling completed."

clean:
	rm -rf $(DEPS)
	rm -rf $(APP)
	rm -rf $(AGENT)

install:
	mkdir -p $(INSTALL_DIR)/stack_bpf
	cp $(APP) $(INSTALL_DIR)
	cp $(BPF_PROG) $(INSTALL_DIR)/stack_bpf
	cp $(AGENT) $(INSTALL_DIR)

