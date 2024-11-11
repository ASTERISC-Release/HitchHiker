SHELL := /bin/bash
PWD := $(shell pwd)
PROJ_DIR := /home/chuqi/GitHub/secure-observability
MODULES_DIR := $(PROJ_DIR)/src/modules
obj-m := 

KERN_DIR := "/home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/linux/out/fvp/mobile_oe"
# CROSS_COMPILE = "/home/chuqi/GitHub/secure-observability/third-parties/gcc-arm-10.3-2021.07-aarch64-aarch64-none-elf/bin/aarch64-none-elf-"

ifeq "$(shell uname -m)" "aarch64"
	CROSS_COMPILE = /usr/bin/
else
	CROSS_COMPILE = /home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
endif
EXTRA_CFLAGS := -I$(MODULES_DIR)/include

MODULE1_NAME := trustd-driver

# module object
obj-m += $(MODULE1_NAME).o

# dependencies
$(MODULE1_NAME)-objs := trustd_driver.o memlib.o exception_table.o

all: 
	make -C $(KERN_DIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=${CROSS_COMPILE} modules
	rm -rf *.mod* .*.cmd *.symvers *.order

clean:
	make -C $(KERN_DIR) M=$(PWD) clean
