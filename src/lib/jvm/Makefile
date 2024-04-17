include ../libvar.mk
INCLUDES = $(BASE_INC)

OUTPUT := jvm_attach

all : $(OUTPUT)
.PHONY: all clean

$(OUTPUT): $(wildcard *.c)
	$(CC) $(CFLAGS) $(INCLUDES) $^ $(LINK_TARGET) -o $@

clean:
	rm -rf $(OUTPUT)
