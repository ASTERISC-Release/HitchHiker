#!/bin/bash
# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 
# define variables
## workspace
DEV_WORKSPACE_PLATFORM="fvp"
DEV_WORKSPACE_FS="oe"
# import variables
SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source $SCRIPT_DIR/config.sh 

if [[ $1 == "el2" ]]; then
    # update linux, atf
    log "Preparing EL2 testbed..."
    log "$EL2TEST_DIR/$EL2TEST_ATF => $THIRD_PARTY_DIR/$TF_EVA_DIR"
    log "$EL2TEST_DIR/$EL2TEST_LINUX => $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/linux" 
    ATF_SRC=$EL2TEST_DIR/$EL2TEST_ATF
    LINUX_SRC=$EL2TEST_DIR/$EL2TEST_LINUX
elif [[ $1 == "emu" ]]; then
    # update emulate linux, atf
    log "Preparing juno emulate testbed..."
    log "$EMU_DIR/$EMU_ATF => $THIRD_PARTY_DIR/$TF_EVA_DIR"
    log "$EMU_DIR/$EMU_LINUX => $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/linux"
    ATF_SRC=$EMU_DIR/$EMU_ATF
    LINUX_SRC=$EMU_DIR/$EMU_LINUX
else
    log "Preparing normal testbed..."
    ATF_SRC=$EMU_DIR/$TF_EVA_DIR
    LINUX_SRC=$SRC_DIR/linux
    if [[ $1 == "dev" ]]; then
        LINUX_SRC=$SRC_DIR/linux_dev
    fi
    log "$ATF_SRC => $THIRD_PARTY_DIR/$TF_EVA_DIR"
    log "$LINUX_SRC => $THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/linux" 
fi

ATF_DST=$THIRD_PARTY_DIR/$TF_EVA_DIR
LINUX_DST=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/linux

if [ -d $ATF_DST ]; then
    echo "Cleaning existing $ATF_DST"
    unlink $ATF_DST
fi
if [ -d $LINUX_DST ]; then
    echo "Cleaning existing $LINUX_DST"
    unlink $LINUX_DST
fi

ln -s $ATF_SRC $ATF_DST
ln -s $LINUX_SRC $LINUX_DST
