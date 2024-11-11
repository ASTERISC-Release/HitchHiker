#!/bin/bash

# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 

# cross compile
CROSS_COMPILE32=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-
# CROSS_COMPILE64=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/tools/gcc/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
CROSS_COMPILE64=$CROSS_COMPILE

# follow common.mk
OPTEE_OS_PATH=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/optee/optee_os
OPTEE_CLIEANT_PATH=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/optee/optee_client

CCACHE=$(which ccache)

CFG_TEE_CORE_LOG_LEVEL=3
DEBUG=1

# platform and flavor
OPTEE_OS_PLATFORM="vexpress-fvp"
# OPTEE_OS_FLAVOR="fvp"

# set out and 64 bit mode
OPTEE_EXTRA_FLAGS="O=out/arm CFG_ARM64_core=y"
OPTEE_OS_COMMON_FLAGS=$OPTEE_EXTRA_FLAGS
# platform
OPTEE_OS_COMMON_FLAGS+=" PLATFORM=${OPTEE_OS_PLATFORM}"
# OPTEE_OS_COMMON_FLAGS+=" PLATFORM_FLAVOR=${OPTEE_OS_FLAVOR}"

# set 32-bit cross compile
OPTEE_OS_COMMON_FLAGS+=" CROSS_COMPILE=${CROSS_COMPILE32}"
# set 64-bit cross compile
OPTEE_OS_COMMON_FLAGS+=" CROSS_COMPILE_core=${CROSS_COMPILE64}"
#
OPTEE_OS_COMMON_FLAGS+=" CROSS_COMPILE_ta_arm64=${CROSS_COMPILE64}"
OPTEE_OS_COMMON_FLAGS+=" CROSS_COMPILE_ta_arm32=${CROSS_COMPILE32}"
#
OPTEE_OS_COMMON_FLAGS+=" CFG_TEE_CORE_LOG_LEVEL=${CFG_TEE_CORE_LOG_LEVEL}"
OPTEE_OS_COMMON_FLAGS+=" DEBUG=${DEBUG}"
# fvp
OPTEE_OS_COMMON_FLAGS+=" CFG_ARM_GICV3=y"

# echo 
echo "flags: $OPTEE_OS_COMMON_FLAGS"

# make
export CROSS_COMPILE32=$CROSS_COMPILE32
export CROSS_COMPILE64=$CROSS_COMPILE64
if [[ $1 == "build" ]]; then
    make -C ${OPTEE_OS_PATH} ${OPTEE_OS_COMMON_FLAGS}
elif [[ $1 == "clean" ]]; then
    make -C ${OPTEE_OS_PATH} ${OPTEE_OS_COMMON_FLAGS} clean
else
    echo "./optee_build.sh build/clean"
fi