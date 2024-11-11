#!/bin/bash

# this script need to be run on the board rather than the client machine.
resdir=/tmp/eva_redis
rm -rf $resdir
mkdir -p $resdir

IP=192.168.2.2
PORT=6379
NUM_PER_CLI=10000
CONNS_PER_THREAD=50
THREADS=2
DSIZE=32
PATT="S:R"

bench="memtier_benchmark"

function run_test() {
	idx=$1
	cd /tmp;
	# use a single file
	# set:get 1:9
	echo "<---------- begin iter $i ------------->"
	$bench -s $IP -p $PORT -c $CONNS_PER_THREAD -n $NUM_PER_CLI -t $THREADS \
		-d $DSIZE --key-pattern $PATT --ratio 1:9 -P redis --hide-histogram --pipeline 4 2>&1 \
	    	| grep -E "Type|---|Sets|Gets|Totals" | tee -a $resdir/res.tmp
	echo "<----------done, sleep 2--------------->"
	sleep 2
}

ITER=10
for i in $(seq 1 $ITER); do
	run_test $i
done

# generate report

total_ops_sec=0
count=0
while IFS= read -r line; do
	if [[ $line == Totals* ]]; then
		ops_sec=$(echo "$line" | awk '{print $2}')
		total_ops_sec=$(bc <<< "$total_ops_sec + $ops_sec")
		count=$((count + 1))
	fi
done < $resdir/res.tmp

avg_ops_sec=$(bc <<< "scale=2; $total_ops_sec / $count")
echo -e "\nAvg ops_sec: $avg_ops_sec" | tee -a $resdir/res.tmp
