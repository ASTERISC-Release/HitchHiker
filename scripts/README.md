## Scripts Description

These scripts are help to automatically create the building environment for FVP platform based on linaro's toolchains.

*Project Directory*:
- `/Path/to/this/repo/secure-observability`/
  - `scripts/` (these scripts)
  - `third-parties/` (This directory will be created by these scripts)
    - `Base_RevC_AEMvA_pkg/` (Contains ARM FVP Base_RevC Model)
    - `disks/` (Contains the virtual disk images created by `dd if=/dev/zero ...`)
    - `dev_workspace/` (Contains Linaro's workspace of software stacks)



### config.sh

This script is served as the source file for all the configurations.

### env_fetch.sh

This script is used for fetching all the required environments and build up the dirctories to form the *Project Directory*.

Run `./env_fetch.sh` to see the usage.

```bash
./env_fetch cross_compile
./env_fetch prerequisite 
./env_fetch fvp_model
./env_fetch tf
```

### env_build.sh && atf_build.sh

This script is used for incremental build for existing softwares (e.g., linux, u-boot)
```bash
./env_build.sh -s linux all     # re-build the linux
./env_build.sh -s uboot all     # re-build the uboot
./atf_build.sh all all          # re-build the atf
```

### start.sh 

This script is used for starting the FVP model.
```bash
./start.sh
```