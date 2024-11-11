PWD         := $(shell pwd) 
KVERSION    := $(shell uname -r)

KERN_DIR := "/home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/linux/out/juno/mobile_oe"

ifeq "$(shell uname -m)" "aarch64"
	CROSS_COMPILE = /usr/bin/
else
	CROSS_COMPILE = /home/chuqi/GitHub/secure-observability/third-parties/dev_workspace/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
endif

MODULE_NAME  = enable_pmu
obj-m       := $(MODULE_NAME).o
$(MODULE_NAME)-objs := enable_arm_pmu.o

all:
	$(MAKE) -C $(KERN_DIR) M=$(PWD) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) modules
	rm -rf *.mod* .*.cmd *.symvers *.order
clean:
	make -C $(KERN_DIR) M=$(PWD) clean
