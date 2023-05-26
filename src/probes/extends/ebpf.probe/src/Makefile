include mk/var.mk

APPS = $(filter ./%/, $(dir $(shell find . -name Makefile)))

.PHONY: all clean install
all: apps
apps:
	$(foreach app, $(APPS), make -s -C $(app) || exit $$?;)

clean:
	$(foreach app, $(APPS), make -s clean -C $(app);)

install:
	$(foreach app, $(APPS), make -s install -C $(app) || exit $$?;)
