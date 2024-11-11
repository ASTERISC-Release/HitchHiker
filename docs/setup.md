## CCA FVP Setup

[News!] [CCA Awakens on Arm’s Modelling Platform](https://www.trustedfirmware.org/blog/cca-awakens-on-arms-modelling-platform/)

### Host tools 

Install the cross-compile toolchain from the [GNU-A](https://developer.arm.com/downloads/-/gnu-a) site: [gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf](https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf.tar.xz?rev=9d9808a2d2194b1283d6a74b40d46ada&hash=F089155D2232ED5D4797B1F7808A70E4)


### Software

#### Armv-A Base AEM FVP ([official download](https://developer.arm.com/downloads/-/arm-ecosystem-models))

The Armv-A Base AEM FVP (Fixed Virtual Platform) is an evolution of the base platform, enhanced to support the exploration of system level virtualization.
It is an Architecture Envelope Model (AEM) which incorporates two AEM clusters, each of which can be configured with up to four cores.

Official User guide: [Armv-A Base AEM FVP platform software user guide](https://gitlab.arm.com/arm-reference-solutions/arm-reference-solutions-docs/-/blob/master/docs/aemfvp-a/user-guide.rst).

1. Download FVP
```bash
wget https://developer.arm.com/-/media/Files/downloads/ecosystem-models/FVP_Base_RevC-2xAEMvA_11.19_14_Linux64.tgz
```

2. Install prerequisite packages
```bash
sudo apt-get update
sudo apt-get install make autoconf autopoint bc bison build-essential curl \
    device-tree-compiler dosfstools flex gettext-base git libssl-dev m4 \
    mtools parted pkg-config python python3-distutils rsync unzip uuid-dev \
    wget acpica-tools fuseext2 iasl
```

3. Enable network on Armv-A Base AEM FVP

The Armv-A Base AEM FVP supports virtual ethernet interface to allow networking support, used for the software executed by the Armv-A Base AEM FVP. 
If support for networking is required, the host TAP interface has to be set up before the Armv-A Base AEM FVP is launched. 
To set up the TAP interface, execute the following commands on the host machine.

- Install libvirt-bin

If you running Ubuntu 20.04 as your host:
```bash
sudo apt install libvirt-daemon-system libvirt-clients bridge-utils
```

If you running Ubuntu 18.04 as your host:
```bash
sudo apt-get install libvirt-bin
```

Note: The above command creates the network interface `virbr0` with the IP address 192.168.122.1. 
This can be checked with the command `ifconfig`.
If the interface is not created, run the following command to restart the `libvirt` daemon.

```bash
sudo systemctl restart libvirt-bin.service
```

- Create a tap interface named 'tap0'

```bash
sudo ip tuntap add dev tap0 mode tap user $(whoami)
sudo ifconfig tap0 0.0.0.0 promisc up
sudo brctl addif virbr0 tap0
```

+ Remove system start-up service in FVP:

```bash
ls /etc/init.d/  # list system services
update-rc.d -f 'service_name' remove
```

#### TF-A ([Trusted Firmware](https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git))

* Official Github: [arm-trusted-firmware](https://github.com/ARM-software/arm-trusted-firmware)
* Official document: [full documentation](https://www.trustedfirmware.org/docs/tf-a)

To support Arm CCA hardware features, we have to download its supported trusted firmware (ATF or TF-A).

Download the version [arm_cca_v0.3](https://git.trustedfirmware.org/TF-A/trusted-firmware-a.git/tag/?h=arm_cca_v0.3)

#### Arm Development Platform Software (Recommanded)

The development platform software is provided by Linaro.
This release supports the software stack for AEMv8-A Base FVP, and it includes the trusted firmware, U-Boot, and so on.

[TBC (see the script `fetch_env.sh` first.)]

#### Arm Reference Platform (Optional)

```
conda install -c eumetsat Expect
(python2) pip install pycrypto
```

then 

```sh
## Your chosen configuration is shown below:

    +---------------+-------------------------------------------------------------------------+
    | Workspace     | /home/chuqi/GitHub/log-integrity/third-parties/arm-reference-platforms/ |
    | Platform      | Armv8-A Base Platform with 64-bit software stack                        |
    | Type          | Build from source                                                       |
    | Release       | refs/tags/ARMLT-19.10                                                   |
    | Configuration | Linaro/ArmLT Latest Stable Kernel + OpenEmbedded LAMP                   |
    +---------------+-------------------------------------------------------------------------+

The following software components are included:

    +-----------------------------------+
    | Trusted Firmware-A                |
    | OP-TEE                            |
    | Linaro/ArmLT Latest Stable Kernel |
    | OpenEmbedded LAMP                 |
    +-----------------------------------+
```
