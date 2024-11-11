#!/bin/bash

# this script need to be run on the board rather than the client machine.
NUM=10000
resdir=/tmp/emp_memcached
rm -rf $resdir
mkdir -p $resdir

IP=192.168.2.2
PORT=11211
SREQS_PER_CLI=1000
GREQS_PER_CLI=9000
CONNS_PER_THREAD=50
THREADS=2
DSIZE=32
PATT="S:S"

bench="memtier_benchmark"

function run_test() {
	idx=$1
	cd /tmp;
	# set
	time $bench -s $IP -p $PORT -c $CONNS_PER_THREAD -n $SREQS_PER_CLI -t $THREADS \
		    -d $DSIZE --key-pattern $PATT --ratio 1:0 -P memcache_text --hide-histogram --pipeline 4 2>&1 \
	            | grep -E "Type|---|Sets|Gets|Waits|Totals|real|sys|user" | tee $resdir/res.$idx.set
	# get
	time $bench -s $IP -p $PORT -c $CONNS_PER_THREAD -n $GREQS_PER_CLI -t $THREADS --key-minimum 1000\
                    -d $DSIZE --key-pattern $PATT --ratio 0:1 -P memcache_text --hide-histogram --pipeline 4 2>&1 \
                    | grep -E "Type|---|Sets|Gets|Waits|Totals|real|sys|user" | tee $resdir/res.$idx.get
	echo "<----------done, sleep 2--------------->"
	sleep 2
}

for i in 0 1 2 3 4; do
	run_test $i
done
