include ../mk/var.mk
INCLUDES = $(BASE_INC)
INCLUDES += -I$(ROOT_DIR)/../l7probe
INSTALL_DIR=/opt/gala-gopher/extend_probes
APP := l7probe
SRC_CPLUS := $(wildcard *.cpp)
SRC_CPLUS += $(CPLUSFILES)

BPF_C := $(wildcard bpf/*.bpf.c)
BPF_PROG := $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
DEPS := $(patsubst %.bpf.c, %.bpf.o, $(BPF_C))
DEPS += $(patsubst %.bpf.c, %.skel.h, $(BPF_C))
DEPS += $(patsubst %.cpp, %.o, $(SRC_CPLUS))

SRC_C := $(filter-out $(BPF_C), $(wildcard *.c))
SRC_C += $(CFILES)

.PHONY: all clean install

all: pre deps app
pre: $(OUTPUT)
deps: $(DEPS)
# build bpf code
%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

# build skel.h
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# build c++ files
%.o: %.cpp
	$(C++) -c $^ $(CXXFLAGS) $(INCLUDES) -o $@

app: $(APP)
%: %.c $(SRC_C)
	$(CC) $(CFLAGS) $(patsubst %.cpp, %.o, $(SRC_CPLUS))  $(INCLUDES) $^ $(LDFLAGS) $(LINK_TARGET) -o $@
	@echo $@ "compiling completed."

clean:
	rm -rf $(DEPS)
	rm -rf $(APP)

install:
	mkdir -p $(INSTALL_DIR)/l7_bpf
	cp $(APP) $(INSTALL_DIR)
	cp $(BPF_PROG) $(INSTALL_DIR)/l7_bpf