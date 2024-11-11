#!/bin/bash

# this script need to be run on the board rather than the client machine.
resdir=/tmp/emp_redis
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
	# set:get 1:9
	$bench -s $IP -p $PORT -c $CONNS_PER_THREAD -n $NUM_PER_CLI -t $THREADS \
		-d $DSIZE --key-pattern $PATT --ratio 1:9 -P redis --hide-histogram --pipeline 4 2>&1 \
	    	| grep -E "Type|---|Sets|Gets|Waits|Totals|real|sys|user" | tee $resdir/res.$idx
	echo "<----------done, sleep 2--------------->"
	sleep 2
}

for i in 0 1 2 3 4; do
	run_test $i
done
