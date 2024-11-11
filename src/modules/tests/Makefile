SHELL := /bin/bash
PWD := $(shell pwd)
PROJ_DIR := /home/chuqi/GitHub/secure-observability
MODULES_DIR := $(PROJ_DIR)/src/modules

# EXTRA_CFLAGS := -march=armv8.4-a

obj-m := 

# KERN_DIR := "/home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/linux/out/fvp/mobile_oe"
KERN_DIR := "/home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/linux/out/juno/mobile_oe"
ifeq "$(shell uname -m)" "aarch64"
	CROSS_COMPILE = /usr/bin/
else
	CROSS_COMPILE = /home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
endif

EXTRA_CFLAGS := -I$(MODULES_DIR)/include -I$(MODULES_DIR)/include/tests 
# MODULE_NAME = rmi_test_gpt
# obj-m := $(MODULE_NAME).o 
# obj-m += enc_test.o

EXEC1 := cma_driver
EXEC2 := s2pt_driver

# obj-m += $(EXEC1).o
# obj-m += $(EXEC2).o

# obj-m += sata_replay.o
# obj-m += sata_replay_el3.o
# obj-m += sata_replay1.o
# obj-m += sata_replay_el1.o
# obj-m += sata_replay_el1_raw.o

# obj-m += empirical_gpt.o


obj-m += empirical_s2pt.o
obj-m += sata_replay_juno.o

all: 
	make -C $(KERN_DIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=${CROSS_COMPILE} modules
	rm -rf *.mod* .*.cmd *.symvers *.order

clean:
	make -C $(KERN_DIR) M=$(PWD) clean
