#!/bin/bash

DST="/home/chuqi/GitHub/secure-observability/third-parties/trusted-firmware-a-arm_cca_v0.3"

if [[ $1 == "dev" ]]; then
	unlink $DST
	ln -s /home/chuqi/GitHub/secure-observability/src/trusted-firmware-a-arm_cca_v0.3 $DST
	echo "/home/chuqi/GitHub/secure-observability/src/trusted-firmware-a-arm_cca_v0.3 => $DST"
else
	unlink $DST
	echo "/home/chuqi/GitHub/SHELTER/shelter_monitor => $DST"
	ln -s /home/chuqi/GitHub/SHELTER/shelter_monitor $DST
fi
