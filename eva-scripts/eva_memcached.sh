#!/bin/bash

# this script need to be run on the board rather than the client machine.
fname=$1
resdir=/tmp/eva_memcached
resfile=$resdir/res.tmp.$fname
rm -rf $resfile
mkdir -p $resdir


IP=192.168.2.2
PORT=11211
SREQS_PER_CLI=1000
GREQS_PER_CLI=1000
CONNS_PER_THREAD=50
THREADS=2
DSIZE=32
PATT="S:S"

bench="memtier_benchmark"

function run_test() {
	idx=$1
	cd /tmp;
	# set
	output=$($bench -s $IP -p $PORT -c $CONNS_PER_THREAD -n $SREQS_PER_CLI -t $THREADS \
		    -d $DSIZE --key-pattern $PATT --ratio 1:0 -P memcache_text --hide-histogram --pipeline 4 2>&1 \
	            | grep -E "Type|---|Sets|Gets|Totals")
	
	# title
	if [[ $idx -eq 1 ]]; then
		title=$(grep -E "^Type|---$" <<< "$output")
		echo "$title" | tee $resfile
	fi
	echo "$(grep -E "^Sets" <<< "$output")" | tee -a $resfile
	set_ops=$(echo "$output" | grep -E "^Sets" | awk '{print $2}')
	# get
	output=$($bench -s $IP -p $PORT -c $CONNS_PER_THREAD -n $GREQS_PER_CLI -t $THREADS --key-minimum 1000\
                    -d $DSIZE --key-pattern $PATT --ratio 0:1 -P memcache_text --hide-histogram --pipeline 4 2>&1 \
                    | grep -E "Type|---|Sets|Gets|Totals")
	echo "$(echo "$output" | grep -E "Gets")" | tee -a $resfile
	get_ops=$(echo "$output" | grep -E "Gets" | awk '{print $2}')
	# time
	total_time=$(bc <<< "scale=2; $SREQS_PER_CLI * $CONNS_PER_THREAD * $THREADS / $set_ops + \
						          $GREQS_PER_CLI * $CONNS_PER_THREAD * $THREADS / $get_ops")
	echo "Total-time: $total_time" | tee -a $resfile
	echo "<----------finish iter $idx--------------->"
	sleep 2
}

ITER=10
for i in $(seq 1 $ITER); do
	run_test $i
done


# generate report
alliter_time=0
all_setops=0
all_getops=0
count=0
set_count=0
get_count=0
while IFS= read -r line; do
	if [[ $line == Total-time* ]]; then
		per_time=$(echo "$line" | awk '{print $2}')
		alliter_time=$(bc <<< "$alliter_time + $per_time")
		count=$((count + 1))
	elif [[ "$line" == *"Sets"* ]]; then
		per_setops=$(echo "$line" | awk '{print $2}')
		all_setops=$(bc <<< "$all_setops + $per_setops")
		set_count=$((set_count + 1))
	elif [[ "$line" == *"Gets"* ]]; then
		per_getops=$(echo "$line" | awk '{print $2}')
		all_getops=$(bc <<< "$all_getops + $per_getops")
		get_count=$((get_count + 1))
	fi
done < $resfile

avg_time=$(bc <<< "scale=2; $alliter_time / $count")
avg_setops=$(bc <<< "scale=2; $all_setops / $set_count")
avg_getops=$(bc <<< "scale=2; $all_getops / $get_count")
echo -e "\nAvg time: $avg_time. Avg setops: $avg_setops. Avg getops: $avg_getops." | tee -a $resfile
