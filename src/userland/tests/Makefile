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
CFLAGS := -g -static -I$(MODULES_DIR)/include


UL_SRC = $(wildcard $(PWD)/*.c)
UL_OBJ = $(patsubst %.c, %.o, $(UL_SRC))

EXEC := tl-test
EXEC1 := sata-test

all: $(EXEC) $(EXEC1)

$(EXEC): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC).o -o $@

$(EXEC1): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC1).o -o $@

$(UL_OBJ): %.o:%.c
	$(CC) $(CFLAGS) $< -c

.PHONY: clean
clean:
	rm -rf *.o $(EXEC)
