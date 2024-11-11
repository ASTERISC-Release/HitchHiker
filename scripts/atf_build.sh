#!/bin/bash
# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 
# define variables
# default workspace is fvp
DEV_WORKSPACE_PLATFORM="fvp"
DEV_WORKSPACE_FS="oe"
# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 

# enable optee
OPTEE_ENABLE=0
RME_ENABLE=1

echo "OPTEE_ENABLE=${OPTEE_ENABLE}"
echo "RME_ENABLE=${RME_ENABLE}"

EVA=0

__print_usage()
{
	log "Usage: atf_build.sh -p [juno|fvp] [all] -e"
	log
	log "atf_build.sh: Builds the arm-trusted-firmware for the"
	log "target system environment."
	log
    log "Supported softwares are - linux/uboot/all"
	log "Supported build commands are - clean/build/package/all"
	log
	exit 0
}

env_build_parse_params() {
	#Parse the named parameters
	while getopts "p:he" opt; do
		case $opt in
            p)
                DEV_WORKSPACE_PLATFORM="$OPTARG"
                ;;
            e)
                EVA=1
                ;;
            h)
                __print_usage
                return
                ;;
		esac
	done

	BUILD_CMD=${@:$OPTIND:1}
}

env_build_parse_params $@

# BUILD flags
if [[ "$(uname -m)" == "aarch64" ]]; then
    CROSS_COMPILE="/usr/bin/"
fi
ATF_COMMON_FLAGS="CROSS_COMPILE=${CROSS_COMPILE}"
ATF_COMMON_FLAGS+=" PLAT=$DEV_WORKSPACE_PLATFORM"
ATF_COMMON_FLAGS+=" ARCH=aarch64"

if [[ $DEV_WORKSPACE_PLATFORM == "fvp" ]]; then
    ATF_COMMON_FLAGS+=" DEBUG=1"
    LOG_LEVEL=40
    ATF_COMMON_FLAGS+=" BL33=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/output/fvp/components/fvp/uboot.bin"
elif [[ $DEV_WORKSPACE_PLATFORM == "juno" ]]; then
    ATF_COMMON_FLAGS+=" BL33=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/output/juno/components/juno/uboot.bin"
    ATF_COMMON_FLAGS+=" DEBUG=0"
    ATF_COMMON_FLAGS+=" V=1"
    LOG_LEVEL=1
    ATF_COMMON_FLAGS+=" SCP_BL2=$THIRD_PARTY_DIR/scp_bl2.bin"
fi

ATF_COMMON_FLAGS+=" LOG_LEVEL=$LOG_LEVEL"

# FVP
if [[ $DEV_WORKSPACE_PLATFORM == "fvp" ]]; then
    if [[ $OPTEE_ENABLE == 1 ]]; then
        ## optee
        OPTEE_OS_PATH=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/optee/optee_os
        OPTEE_OS_HEADER_V2_BIN=$OPTEE_OS_PATH/out/arm/core/tee-header_v2.bin
        OPTEE_OS_PAGER_V2_BIN=$OPTEE_OS_PATH/out/arm/core/tee-pager_v2.bin
        OPTEE_OS_PAGEABLE_V2_BIN=$OPTEE_OS_PATH/out/arm/core/tee-pageable_v2.bin

        ATF_COMMON_FLAGS+=" SPD=opteed"
        ATF_COMMON_FLAGS+=" BL32=${OPTEE_OS_HEADER_V2_BIN}"
        ATF_COMMON_FLAGS+=" BL32_EXTRA1=${OPTEE_OS_PAGER_V2_BIN}"
        ATF_COMMON_FLAGS+=" BL32_EXTRA2=${OPTEE_OS_PAGEABLE_V2_BIN}"
        ATF_COMMON_FLAGS+=" CTX_INCLUDE_AARCH32_REGS=0"
        ATF_COMMON_FLAGS+=" FVP_USE_GIC_DRIVER=FVP_GICV3"
        ATF_COMMON_FLAGS+=" ARM_TSP_RAM_LOCATION=tdram"
    elif [[ $RME_ENABLE == 1 && $2 != "eva" && $2 != "emu" ]]; then     #rme
        # test GICV2
        # ATF_COMMON_FLAGS+=" FVP_USE_GIC_DRIVER=FVP_GICV2"
        # ATF_COMMON_FLAGS+=" FVP_HW_CONFIG_DTS=fdts/fvp-base-gicv2-psci.dts"
        # use GICV3
        ATF_COMMON_FLAGS+=" FVP_HW_CONFIG_DTS=fdts/fvp-base-gicv3-psci-1t.dts"
        ATF_COMMON_FLAGS+=" ARM_DISABLE_TRUSTED_WDOG=1"
        ATF_COMMON_FLAGS+=" ENABLE_HHKRD=1"
        
    else                    # eva
        ATF_COMMON_FLAGS+=" CTX_INCLUDE_AARCH32_REGS=0"
        ATF_COMMON_FLAGS+=" FVP_USE_GIC_DRIVER=FVP_GICV3"
        ATF_COMMON_FLAGS+=" FVP_HW_CONFIG_DTS=fdts/fvp-base-gicv3-psci-1t.dts"
        ATF_COMMON_FLAGS+=" ARM_TSP_RAM_LOCATION=tdram"
    fi
fi

build_tf-a() {
    if [ ! -f $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/output/$DEV_WORKSPACE_PLATFORM/components/$DEV_WORKSPACE_PLATFORM/uboot.bin ]; then
        log_error "[DevWorkspace Error] Build development workspace for $$DEV_WORKSPACE_PLATFORM first."
        exit
    fi

    if [[ $EVA == 1 ]]; then
        log "Building tf-a-eva ($EMU_DIR/$TF_EVA_DIR => $TF_EVA_DIR)..."
        cd $THIRD_PARTY_DIR/$TF_EVA_DIR
    else
        log "Building tf-a ($TF_A_DIR)..."
        cd $THIRD_PARTY_DIR/$TF_A_DIR
    fi
    # clean first
    make clean && make realclean
    # build or all
    if [[ $1 == "build" || $1 == "all" ]]; then

        if [[ $RME_ENABLE == 1 && $2 != "eva" && $DEV_WORKSPACE_PLATFORM != "juno" ]]; then
            ATF_COMMON_FLAGS+=" ENABLE_RME=1"
        fi

        echo "flags: $ATF_COMMON_FLAGS"
        make ${ATF_COMMON_FLAGS} all fip
    fi
    # package or all
    # do nothing
}

build_tf-a $BUILD_CMD
