include ../mk/var.mk
INCLUDES = $(BASE_INC)

APP := stackprobe
AGENT := jvm_agent.so
ATTACH := jvm_attach
CONF_FILE = $(wildcard conf/*.conf)
SRC_CPLUS := $(wildcard *.cpp)
SRC_CPLUS += $(CPLUSFILES)

BPF_C := $(wildcard stack_bpf/*.bpf.c)
BPF_PROG := $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
DEPS = $(BPF_PROG) $(patsubst %.cpp, %.o, $(SRC_CPLUS))

SRC_C := $(wildcard *.c)
SRC_C += $(wildcard conf/*.c)
SRC_C += $(CFILES)

ALL := pre deps app agent attach
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
ifndef JAVA_HOME
	@echo "WARN: environment variable JAVA_HOME not found"
endif
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
	mkdir -p $(CONF_INSTALL_DIR)
	cp $(CONF_FILE) $(CONF_INSTALL_DIR)
	cp $(AGENT) $(INSTALL_DIR)
	cp $(ATTACH) $(INSTALL_DIR)

