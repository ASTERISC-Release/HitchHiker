SHELL := /bin/bash
PWD := $(shell pwd)

PROJ_DIR := /home/chuqi/GitHub/secure-observability

MODULES_DIR := $(PROJ_DIR)/src/modules
USERLAND_DIR := $(PROJ_DIR)/src/userland

ifeq "$(shell uname -m)" "aarch64"
	CC := /usr/bin/gcc
else
	CC := "/home/chuqi/GitHub/secure-observability/third-parties/gcc-arm-10.3-2021.07-aarch64-aarch64-none-elf/bin/aarch64-none-elf-"
endif
CFLAGS := -g -I$(MODULES_DIR)/include/tests

# SRC
UL_SRC = $(wildcard $(PWD)/*.c)
UL_OBJ = $(patsubst %.c, %.o, $(UL_SRC))

SRC := cma-user.c 
OBJ := $(SRC:.c=.o)

EXEC := cma-user
EXEC2 := tzasc-user
EXEC3:= s2pt-user
EXEC4 := pidloop

all: $(EXEC) $(EXEC2) $(EXEC3) $(EXEC4)

# $(EXEC): $(SRC)
# 	$(CC) $(CFLAGS) -o $(EXEC) $(SRC)
$(EXEC): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC).o -o $@

$(EXEC2): $(UL_OBJ) 
	$(CC) $(CFLAGS) $(EXEC2).o -o $@

$(EXEC3): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC3).o -o $@

$(EXEC4): $(UL_OBJ)
	$(CC) $(CFLAGS) $(EXEC4).o -o $@

$(UL_OBJ): %.o:%.c
	$(CC) $(CFLAGS) -c $< 

.PHONY: clean
clean:
	rm -rf *.o $(EXEC)
	rm -rf *.o $(EXEC2)
	rm -rf *.o $(EXEC3)
	rm -rf *.o $(EXEC4)
