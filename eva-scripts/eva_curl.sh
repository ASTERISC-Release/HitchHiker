#!/bin/bash

#should run on board
fname=$1
resdir=/tmp/eva_curl
resfile=$resdir/res.tmp.$fname
rm -rf $resfile
mkdir -p $resdir

IP="192.168.2.1:8880"

GETS=1000

function payload() {
    tottime=0.0
    for i in $(seq 1 $GETS); do
        thistime=$({ time curl $IP -s -o /dev/null -H 'Cache-Control: no-cache, no-store'; } 2>&1 \
                    | grep -E 'real' \
                    | awk '{print $2}' | sed 's/[^0-9.]//g')
        tottime=$(echo "$tottime" + "$thistime" | bc)
    done
    echo $tottime
}

function run_test() {
    payload | tee -a $resfile
    echo "<--------- iter $i finish --------------->"
}

ITER=1
for i in $(seq 1 $ITER); do
    run_test $i
done


# report
total_time=0
count=0
while IFS= read -r line; do
		total_time=$(bc <<< "$total_time + $line")
		count=$((count + 1))
done < $resfile

avg_time=$(bc <<< "scale=5; $total_time / $count")
echo -e "\nAvg time: $avg_time" | tee -a $resfile