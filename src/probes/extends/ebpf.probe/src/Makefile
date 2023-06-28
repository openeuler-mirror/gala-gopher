include mk/var.mk

APPS_ALL = $(filter ./%/, $(dir $(shell find . -name Makefile)))
APPS = $(filter-out $(EBPF_TAILOR_PROBES) , $(APPS_ALL))

.PHONY: all clean install
all: apps
apps:
	$(foreach app, $(APPS), make -s -C $(app);)

clean:
	$(foreach app, $(APPS), make -s clean -C $(app);)

install:
	$(foreach app, $(APPS), make -s install -C $(app);)
