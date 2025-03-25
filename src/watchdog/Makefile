C++ = g++
CC = gcc
APP = watchdog

CFLAGS := -g -O2 -Wall -Werror -fstack-protector-strong
LDFLAGS := -lpthread
INCLUDES := -I/usr/include

SRCS = watchdog.c

all: $(APP)
.PHONY: clean install

$(APP): $(SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) $(LINK_TARGET) -o $@ $^

clean:
	rm -f *.o $(APP)

install: $(APP)
	@echo "installing watchdog..."