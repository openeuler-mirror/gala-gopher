# force BPF programs to use CO-RE helpers regardless of whether kernel BTF is
# present in the build environment
BTF_ENABLE_OVERRIDE := ON

include ../mk/var.mk

APP := kafkaprobe

BPF_C := $(wildcard *.bpf.c)
SRC_C := $(filter-out $(BPF_C), $(wildcard *.c))
SRC_C += $(CFILES)

OBJ_KERN := $(patsubst %.c, %.o, $(BPF_C))

SRC_CPLUS := $(wildcard *.cpp)
SRC_CPLUS += $(abspath $(CPLUSFILES))
OBJ_CPLUS = $(patsubst %.cpp, %.o, $(SRC_CPLUS))

BPF_CFLAGS := -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -target bpf

all: $(APP) $(OBJ_KERN)

.PHONY: clean install

# build c++ files
$(OBJ_CPLUS): %.o: %.cpp
	$(C++) -c $^ $(CXXFLAGS) $(BASE_INC) -o $@

$(APP): $(SRC_C) $(OBJ_CPLUS)
	$(CC) $(CFLAGS) $(BASE_INC) $(LDFLAGS) $(LINK_TARGET) -o $@ $^

$(OBJ_KERN): $(BPF_C) 
	$(CLANG) $(CLANGFLAGS) $(BPF_CFLAGS) $(BASE_INC) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -rf $(APP) $(OBJ_KERN)

install:
	mkdir -p $(INSTALL_DIR)
	cp $(APP) $(INSTALL_DIR)
	cp $(OBJ_KERN) $(INSTALL_DIR)
