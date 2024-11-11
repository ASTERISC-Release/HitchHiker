#!/bin/bash

# replace DST=/dev/null to your disk partition
DST=/dev/null

# replace RES_F=result.txt to your result file
RES_F=result.txt

if [ -f $RES_F ];then
	rm $RES_F
fi
dd if=/dev/zero of=$DST bs=4k count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=16k count=1 >> $RES_F 2>&1 
dd if=/dev/zero of=$DST bs=32k count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=64k count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=128k count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=256k count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=512k count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=1M count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=16M count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=64M count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=128M count=1 >> $RES_F 2>&1
dd if=/dev/zero of=$DST bs=256M count=1 >> $RES_F 2>&1
echo "finish."
