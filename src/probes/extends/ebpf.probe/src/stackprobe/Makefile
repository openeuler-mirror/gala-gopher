include ../mk/var.mk
INCLUDES = $(BASE_INC)

APP := stackprobe
AGENT := jvm_agent.so
ATTACH := jvm_attach
SRC_CPLUS := $(wildcard *.cpp)
SRC_CPLUS += $(CPLUSFILES)

BPF_C := $(wildcard stack_bpf/*.bpf.c)
BPF_PROG := $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
DEPS = $(BPF_PROG) $(patsubst %.cpp, %.o, $(SRC_CPLUS))

SRC_C := $(wildcard *.c)
SRC_C += $(CFILES)

ALL := pre deps app agent attach

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
	$(CLANG) $(CFLAGS) -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ 

# build c++ files
%.o: %.cpp
	$(C++) -c $^ $(CXXFLAGS) $(INCLUDES) -o $@

app: $(APP)
%: %.c $(SRC_C)
	$(CC) $(CFLAGS) $(patsubst %.cpp, %.o, $(SRC_CPLUS)) $(INCLUDES) $^ $(LDFLAGS) $(LINK_TARGET) -lcurl -o $@
	@echo $@ "compiling completed."

agent: $(AGENT)
$(AGENT): jvmti/jvm_agent.c
	$(CC) $(CFLAGS) -shared $(INCLUDES) $(JNI_INC) $^ $(LDFLAGS) -o $@
	@echo $@ "compiling completed."

attach: $(ATTACH)
$(ATTACH): jvmti/jvm_attach.c
	$(CC) $(CFLAGS) $(INCLUDES) $^ $(LDFLAGS) -o $@
	@echo $@ "compiling completed."

clean:
	rm -rf $(DEPS)
	rm -rf $(APP)
	rm -rf $(AGENT)
	rm -rf $(ATTACH)

install:
	mkdir -p $(INSTALL_DIR)/stack_bpf
	cp $(APP) $(INSTALL_DIR)
	cp $(BPF_PROG) $(INSTALL_DIR)/stack_bpf
	cp $(AGENT) $(INSTALL_DIR)
	cp $(ATTACH) $(INSTALL_DIR)

