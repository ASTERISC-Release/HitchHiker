#!/bin/bash

SCRIPT_DIR="$(dirname $(readlink -f "$0"))"

source $SCRIPT_DIR/config.sh 

# log files
if [ ! -d $LOG_DIR ]; then
    mkdir -p $LOG_DIR
fi
uart0_log=$LOG_DIR/uart0-fvp.log
uart1_log=$LOG_DIR/uart1-fvp.log
uart2_log=$LOG_DIR/uart2-fvp.log
uart3_log=$LOG_DIR/uart3-fvp.log


FS_IMG_PATH=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/oe.img
# tf-a 
ATF_OUT_PATH=$THIRD_PARTY_DIR/$TF_A_DIR/build/fvp/debug
ATF_EVA_OUT_PATH=$THIRD_PARTY_DIR/$TF_EVA_DIR/build/fvp/debug
# optee
OPTEE_ENABLE=0
RME_ENABLE=1
RUN_ATF_EVA=0
# eva
if [[ $1 == "eva" ]]; then
    RUN_ATF_EVA=1
fi

if [[ $1 == "debug" || $2 == "debug" ]]; then
    DEBUG=1
fi

# fvp launch options
FVP_LAUNCH_OPS="-C pctl.startup=0.0.0.0"
if [[ $DEBUG == 1 ]]; then
    FVP_LAUNCH_OPS += " --cadi-server"
fi
if [[ $OPTEE_ENABLE == 1 || $RUN_ATF_EVA == 1 ]]; then
    FVP_LAUNCH_OPS+=" -C bp.secure_memory=1"
    FVP_LAUNCH_OPS+=" -C bp.tzc_400.diagnostics=1"
else
    FVP_LAUNCH_OPS+=" -C bp.secure_memory=0"
    # enable rme
    if [[ $RME_ENABLE == 1 && $RUN_ATF_EVA != 1 ]]; then 
        FVP_LAUNCH_OPS+=" -C cluster0.has_rme=1" 
        FVP_LAUNCH_OPS+=" -C cluster1.has_rme=1"
    fi
fi
FVP_LAUNCH_OPS+=" -C cluster0.NUM_CORES=4"
FVP_LAUNCH_OPS+=" -C cluster1.NUM_CORES=4"
FVP_LAUNCH_OPS+=" -C cache_state_modelled=0"
FVP_LAUNCH_OPS+=" -C bp.pl011_uart0.untimed_fifos=1"
FVP_LAUNCH_OPS+=" -C bp.pl011_uart0.unbuffered_output=1"
FVP_LAUNCH_OPS+=" -C bp.pl011_uart0.out_file=$uart0_log"
FVP_LAUNCH_OPS+=" -C bp.pl011_uart1.out_file=$uart1_log"
FVP_LAUNCH_OPS+=" -C bp.pl011_uart2.out_file=$uart2_log"
FVP_LAUNCH_OPS+=" -C bp.pl011_uart3.out_file=$uart3_log"
if [[ $RUN_ATF_EVA == 1 ]]; then
    log "FVP based on atf-eva... (${ATF_EVA_OUT_PATH})"
    FVP_LAUNCH_OPS+=" -C bp.secureflashloader.fname=$ATF_EVA_OUT_PATH/bl1.bin"
    FVP_LAUNCH_OPS+=" -C bp.flashloader0.fname=$ATF_EVA_OUT_PATH/fip.bin"
else 
    log "FVP based on atf... (${ATF_OUT_PATH})"
    FVP_LAUNCH_OPS+=" -C bp.secureflashloader.fname=$ATF_OUT_PATH/bl1.bin"
    FVP_LAUNCH_OPS+=" -C bp.flashloader0.fname=$ATF_OUT_PATH/fip.bin"
fi

if [[ "$(uname -m)" != "aarch64" ]]; then
    FVP_LAUNCH_OPS+=" --data cluster0.cpu0=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/output/fvp/fvp-oe/uboot/fvp-base-aemv8a-aemv8a.dtb@0x82000000"  #from linux
fi
FVP_LAUNCH_OPS+=" --data cluster0.cpu0=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/output/fvp/fvp-oe/uboot/ramdisk.img@0x84000000" #fvp/uInitrd-oe.0x84000000 from build-oe-binaries.sh
FVP_LAUNCH_OPS+=" -C bp.ve_sysregs.mmbSiteDefault=0"
FVP_LAUNCH_OPS+=" -C bp.ve_sysregs.exit_on_shutdown=1"
FVP_LAUNCH_OPS+=" -C cluster0.max_32bit_el=-1"
FVP_LAUNCH_OPS+=" -C cluster0.has_v8_7_pmu_extension=2"
FVP_LAUNCH_OPS+=" -C cluster0.has_rndr=1"
FVP_LAUNCH_OPS+=" -C cluster1.max_32bit_el=-1"
FVP_LAUNCH_OPS+=" -C cluster1.has_v8_7_pmu_extension=2"
FVP_LAUNCH_OPS+=" -C cluster1.has_rndr=1"
# use gicv3
FVP_LAUNCH_OPS+=" -C cluster0.gicv3.without-DS-support=1"
FVP_LAUNCH_OPS+=" -C cluster0.gicv3.cpuintf-mmap-access-level=2"
FVP_LAUNCH_OPS+=" -C cluster1.gicv3.without-DS-support=1"
FVP_LAUNCH_OPS+=" -C cluster1.gicv3.cpuintf-mmap-access-level=2"
# FVP_LAUNCH_OPS+=" -C cluster0.gicv3.virtual-lpi-support=0"
# FVP_LAUNCH_OPS+=" -C cluster1.gicv3.virtual-lpi-support=0"
# FVP_LAUNCH_OPS+=" -C gic_distributor.direct-lpi-support=1"


FVP_LAUNCH_OPS+=" -C cluster0.gicv4.mask-virtual-interrupt=1"
FVP_LAUNCH_OPS+=" -C cluster1.gicv4.mask-virtual-interrupt=1"

FVP_LAUNCH_OPS+=" -C bp.virtioblockdevice.image_path=$FS_IMG_PATH"
FVP_LAUNCH_OPS+=" --data cluster0.cpu0=$THIRD_PARTY_DIR/$DEV_WORKSPACE_DIR/output/fvp/fvp-oe/uboot/Image@0x80080000"  #from linux/../Image.mobile_oe
FVP_LAUNCH_OPS+=" -C bp.hostbridge.interfaceName=tap0"
FVP_LAUNCH_OPS+=" -C bp.smsc_91c111.enabled=true"
FVP_LAUNCH_OPS+=" -C bp.smsc_91c111.mac_address=00:02:F7:C1:9F:81"
# test sata disk
# to create a sata disk, use dd if=/dev/zero of=/path/to/satadisk bs=1G count=10
FVP_LAUNCH_OPS+=" -C pci.ahci_pci.ahci.image_path=$THIRD_PARTY_DIR/disks/1.img"
# FVP_LAUNCH_OPS+=" -C pci.ahci_pci.ahci.force_mode=DMA"
# FVP_LAUNCH_OPS+=" -C pci.pcivirtioblockdevice0.image_path=$THIRD_PARTY_DIR/disks/2.img"
# FVP_LAUNCH_OPS+=" -C pci.pcivirtioblockdevice1.image_path=$THIRD_PARTY_DIR/disks/3.img"
# ete & trbe extension 
# FVP_LAUNCH_OPS+=" -C cluster0.has_ete=1"
# FVP_LAUNCH_OPS+=" -C cluster0.has_trbe=1"
# FVP_LAUNCH_OPS+=" -C cluster1.has_ete=1"
# FVP_LAUNCH_OPS+=" -C cluster1.has_trbe=1"

# test gicv2
# FVP_LAUNCH_OPS+=" -C gicv3.gicv2-only=1"

# FVP_LAUNCH_OPS+=" -C gic_distributor.wakeup-on-reset=1"



start_fvp_new() {
    # check tap0 network interface
    ifconfig tap0 > /dev/null 2>&1
    if [ $? != 0 ]; then
        log "Creating network interface tap0..."
        sudo ip tuntap add dev tap0 mode tap user $(whoami)
        sudo ifconfig tap0 0.0.0.0 promisc up
        sudo brctl addif virbr0 tap0
    fi
    $FVP $FVP_LAUNCH_OPS
}

# xterm settings
xrdb -merge ~/.Xresources

# log the options
log "Launch options:"
echo $FVP_LAUNCH_OPS
start_fvp_new
