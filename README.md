# HitchHiker

**Paper:** The HitchHiker's Guide to High-Assurance System Observability Protection with Efficient Permission Switches [link](https://arxiv.org/pdf/2409.04484).

## Overview

This document accompanies the paper and describes how to set up an environment that can be used to run the functional prototype that we described in the paper.

This functional prototype relies on ARM [Fixed Virtual Platform (FVP)](https://developer.arm.com/Tools%20and%20Software/Fixed%20Virtual%20Platforms) that supports the simulation of the whole system and Granule Protection Table (GPT)-based memory protection.

## Environment Setup


You can set up the environment manually based on the scripts.
We assume the host is running Ubuntu 20.04.

TODO: Setting up Linaro ARM reference platform is painful... To ease the environment set up, I will provide an ARM64 Ubuntu 20.04 virtual machine (TBD).


1. Workspace configuration

The file `scripts/config.sh` as well as the directory `configs/` contain all the configurations needed for the building toolchain.
Note that we will release our root file system image for the FVP after the paper's publication. 
Currently, it is replaced with the Linaro openembedded image.

```bash
#!/bin/bash
# packages & sources
export CROSS_COMPILE_SRC="https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf.tar.xz"
export CROSS_COMPILE_SRC_AARCH64="https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-aarch64-aarch64-none-elf.tar.xz"
export FVP_SRC="https://armkeil.blob.core.windows.net/developer/Files/downloads/ecosystem-models/FVP_Base_RevC-2xAEMvA_11.19_14_Linux64.tgz"
export FVP_SRC_AARCH64="https://developer.arm.com/-/media/Files/downloads/ecosystem-models/FVP_Base_RevC-2xAEMvA_11.20_15_Linux64_armv8l.tgz"
export TF_A_SRC="https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git/snapshot/trusted-firmware-a-arm_cca_v0.3.tar.gz"
export ARM_REF_PLAT_SRC="https://git.linaro.org/landing-teams/working/arm/arm-reference-platforms.git"
export DEV_WORKSPACE_SRC="https://git.linaro.org/landing-teams/working/arm/manifest"
export ARN_UBUNTU_IMG_SRC="https://old-releases.ubuntu.com/releases/focal/ubuntu-20.04-live-server-arm64.iso"
export LINARO_CROSS_COMPILE_SRC="https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/aarch64-linux-gnu/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu.tar.xz"
export LINARO_CROSS_COMPILE_GNUEABIHF_SRC="https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz"
export OELAMP_IMG_SRC="https://releases.linaro.org/openembedded/juno-lsk/15.09/lt-vexpress64-openembedded_lamp-armv8-gcc-4.9_20150912-729.img.gz"
# SH
export SH="/bin/bash"
# project structure directories
export SCRIPT_DIR="(dirname(dirname (readlink -f "$0"))"
export PROJ_DIR="(dirname(dirname SCRIPT_DIR)"
export SRC_DIR=$PROJ_DIR/src
export EL2TEST_DIR=$SRC_DIR/empirical_el2
export EMU_DIR=$PROJ_DIR/emulate
export PROJ_CONF_DIR=$PROJ_DIR/configs
export THIRD_PARTY_DIR=$PROJ_DIR/third-parties
export DBG_DIR=$PROJ_DIR/debug 
export LOG_DIR=$PROJ_DIR/debug/logs
# package dsts
export CROSS_COMPILE_DIR="gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf"
export CROSS_COMPILE_DIR_AARCH64="gcc-arm-10.3-2021.07-aarch64-aarch64-none-elf"
export FVP_DIR="Base_RevC_AEMvA_pkg"
export TF_A_DIR="trusted-firmware-a-arm_cca_v0.3"
export TF_EVA_DIR="arm-tf"
export ARM_REF_PLAT_DIR="arm-reference-platforms"
export LINUX_DISTRO_IMG="ubuntu-20.04-live-server-arm64.iso"
export OELAMP_IMG="lt-vexpress64-openembedded_lamp-armv8.img"
export SATA_DIR="satadisks"
...
```

2. Software stack download

Run the script `scripts/env_fetch.sh` to see the commands.
```bash
$ ./scripts/env_fetch.sh
$ Usage: ./env_fetch.sh [all | cross_compile | prerequisite | fvp_model | tf]
```

Directly type the command `./scripts/env_fetch all` to install all the required dependencies.

3. Software stack installation

Run the script `scripts/env_build.sh` and `scripts/atf_build.sh` to see the commands.
```bash
$ ./scripts/env_build.sh
Usage: env_build.sh -s <software> -p [juno|fvp] <command>
env_build.sh: Builds the platform software stack with the
targeted software component.
Supported softwares are - linux/uboot/all
Supported build commands are - clean/build/package/all
```

Type the command `./scripts/env_build.sh -s all -p fvp all` to build the FVP environment.

```bash
$ ./scripts/atf_build.sh
Usage: atf_build.sh -p [juno|fvp] [all] [-e]
atf_build.sh: Builds the arm-trusted-firmware for the
target system environment.
```

Type the command `./scripts/atf_build.sh -p fvp all` to build the secure monitor environment.

4. Start the environment

```bash
$ ./scripts/start.sh
```

**Note**: I recommand enabling an [adeb](https://github.com/joelagnel/adeb) Debian filesystem within the downloaded OpenEmbedded root filesystem. This simplifies package, software, and benchmark download and deployment.

## Usage

* Observability generator 
  
Refer to the source code for HitchHiker's observability generator located under [linux_dev/samples/bpf](src/linux_dev/samples/bpf/) by searching for files with keyword "hitchhiker".

These files provide a minimal port of Aqua Tracee's [tracee.bpf.c](https://github.com/aquasecurity/tracee/blob/main/pkg/ebpf/c/tracee.bpf.c).

Build them and run the HitchHiker observability generator (logger):

```bash
$ /data/hitchhiker_user
Usage: ./hitchhiker_user [OPTIONS]

OPTIONS:
  --time,      -t [SECONDS]        Run the hitchhiker observability logger program for [SECONDS] seconds. Ignored by default.
  --interval,  -i [MICROSECONDS]   Set the hitchhiker protection scheme interval to [MICROSECONDs] us (default 1000us).
  --only-comm, -c [STRING]         Only trace the program named [STRING].
  --only-pid,  -p [PID]            Only trace the process with pid [PID].
  --eval,      -e                  Run in evaluation mode.
  --hhkrd,     -d                  Enable Hitchhiker daemon.
  --audit-log, -s                  Enable audit (syscall) log.
  --app-log,   -a                  Enable application log.
  --net-log,   -n                  Enable network log.
  --help,      -h                  Show this help message and exit.
```

* Log daemon (HkD) management.

Refer to the source code for HitchHiker's protected daemon management located under [tf-a/bl31](src/trusted-firmware-a-arm_cca_v0.3/bl31/). All files with prefix `hhkrd` are related to log daemon management.

You could write and compile an arbitrary process into a log daemon. To load the daemon, please (a) specify the [loader](src/userland/loader/)'s target by editing `#define HHKRD` under [hhkrd_loader.c](src/userland/loader/hhkrd_loader.c), and (b) compile and run the loader.

Start the Hitchhiker daemon:

```bash
$ /data/hhkrd_loader
```

## Evaluation Dataset & Scripts

Evaluation scripts for the server-side programs and Wget are under the directory `eva-scripts/`.
The detailed setup for the applications can be found at [`docs/applications.md`](docs/applications.md).

* [Redis](eva-scripts/eva_redis2.sh)
* [Memcached](eva-scripts/eva_memcached.sh)
* [Apache Httpd](eva-scripts/eva_apache2.sh)
* [Nginx](eva-scripts/emp_nginx.sh)
* [MySQL](eva-scripts/eva_mysql.sh)
* [Wget](eva-scripts/eva_wget.sh)
* OpenSSL

```bash
phoronix-test-suite benchmark pts/openssl
```

* 7-zip

```bash
phoronix-test-suite benchmark pts/compress-7zip
```

* GNU Octave

```bash
phoronix-test-suite benchmark system/octave-benchmark
```
