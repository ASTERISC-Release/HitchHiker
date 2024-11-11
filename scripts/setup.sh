#!/bin/bash

# project structure directories
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
PROJ_DIR="$(dirname $SCRIPT_DIR)"
THIRD_PARTY_DIR=$PROJ_DIR/third-parties

# third party package directories
TF_A_DIR=$THIRD_PARTY_DIR/trusted-firmware-a-2.6

# toolchain 
CROSS_COMPILE=$THIRD_PARTY_DIR/gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf/bin/aarch64-none-elf-


print_config() {
    echo "=== Configurations ==="
    echo "=> THIRD_PARTY_DIR=$PROJ_DIR/third-parties"
    echo "=> CROSS_COMPILE=$CROSS_COMPILE"
}

compile_TF_A() {
    cd $TF_A_DIR
    make clean 
    make CROSS_COMPILE=$CROSS_COMPILE \
         PLAT=fvp \
         ENABLE_RME=1 \
         FVP_HW_CONFIG_DTS=fdts/fvp-base-gicv3-psci-1t.dts \
         DEBUG=1 \
         LOG_LEVEL=40 \
         ARCH=aarch64 \
         ARM_DISABLE_TRUSTED_WDOG=1 \
         BL33=/home/dog/Downloads/codework/arm-reference-platforms-FVP/output/fvp/components/fvp/uboot.bin \
         all fip
}


compile_TF_A