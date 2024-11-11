
```sh
#!/bin/bash
# replace /dev/null to your disk partition (e.g. /dev/sda3)
# NOTE: Create and use an **EMPTY** partition! (e.g. /dev/sdax)
# NOTE: DO NOT use your system partition!
DST=/dev/null

# replace result.txt to your result file
RES_F=result.txt
echo "" > res.txt
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
```