#!/bin/bash

# define variables
#PLATFORM="aemfvp-a"
DEV_WORKSPACE_PLATFORM="fvp"
DEV_WORKSPACE_FS="oe"
DEV_WORKSPACE_LINUX_OE=""

if [[ $DEV_WORKSPACE_FS=="oe" ]]; then
    DEV_WORKSPACE_LINUX_OE="mobile_oe"
fi

# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 

BURN_DIR=$PROJ_DIR/burn-builds
if [ ! -d $BURN_DIR ]; then
    mkdir -p $BURN_DIR
fi

if [[ $1 != "" ]]; then
    ATF_OUT_DIR=$EMU_DIR/$EMU_ATF/build/juno/release
else
    ATF_OUT_DIR=$EMU_DIR/$EMU_ATF/build/juno/debug
fi
DEV_WORKSPACE_OUT_DIR=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/output/juno/juno-oe/uboot

# ATF
cp $ATF_OUT_DIR/bl1.bin $BURN_DIR/
log "$ATF_OUT_DIR/bl1.bin => $BURN_DIR/"

cp $ATF_OUT_DIR/fip.bin $BURN_DIR/
log "$ATF_OUT_DIR/fip.bin => $BURN_DIR/"

# WORKSPACE
cp $DEV_WORKSPACE_OUT_DIR/* $BURN_DIR/
log "$DEV_WORKSPACE_OUT_DIR/* => $BURN_DIR/"