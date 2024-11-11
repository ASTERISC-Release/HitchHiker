SHELL := /bin/bash
PWD := $(shell pwd)

PROJ_DIR := /home/chuqi/GitHub/secure-observability

MODULES_DIR := $(PROJ_DIR)/src/modules
USERLAND_DIR := $(PROJ_DIR)/src/userland

ifeq "$(shell uname -m)" "aarch64"
	CC := /usr/bin/gcc
else
	CC := /home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc
endif
CFLAGS := -g -static -pthread -I$(MODULES_DIR)/include


UL_SRC = $(wildcard $(PWD)/*.c)
UL_OBJ = $(patsubst %.c, %.o, $(UL_SRC))

EXEC = hhkrd-io
EXEC2 = hhkrd-io-test
EXEC3 = omnid
EXEC4 = hhkrd
EXEC5 = td-helloworld

all: $(EXEC) $(EXEC2) $(EXEC3) $(EXEC4) $(EXEC5)

$(EXEC): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC).o -o $@

$(EXEC2): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC2).o -o $@

$(EXEC3): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC3).o -o $@

$(EXEC4): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC4).o -o $@

$(EXEC5): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC5).o -o $@

$(UL_OBJ): %.o:%.c
	$(CC) $(CFLAGS) $< -c

.PHONY: clean
clean:
	rm -rf *.o $(EXEC) $(EXEC2) $(EXEC3) $(EXEC4) $(EXEC5)