include ../../../ebpf.probe/src/mk/var.mk
INCLUDES = $(BASE_INC)

APP := jvmprobe

SRC_CPLUS := $(wildcard *.cpp)
SRC_CPLUS += $(CPLUSFILES)

DEPS = $(patsubst %.cpp, %.o, $(SRC_CPLUS))

SRC_C := $(wildcard *.c)
SRC_C += $(CFILES)

CFLAGS += -DJAVA_AGENT_VER='"$(JAVA_AGENT_VER)"'

.PHONY: all clean install

ALL := pre deps app

all: $(ALL)
pre: $(OUTPUT)
deps: $(DEPS)
# build c++ files
%.o: %.cpp
	$(C++) -c $^ $(CXXFLAGS) $(INCLUDES) -o $@

app: $(APP)
%: %.c $(SRC_C)
	$(CC) $(CFLAGS) $(patsubst %.cpp, %.o, $(SRC_CPLUS)) $(INCLUDES) $^ $(LDFLAGS) $(LINK_TARGET) -o $@
	@echo $@ "compiling completed."

clean:
	rm -rf $(DEPS)
	rm -rf $(APP)

install:
	mkdir -p $(INSTALL_DIR)
	cp $(APP) $(INSTALL_DIR)

