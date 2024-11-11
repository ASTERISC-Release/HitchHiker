#!/bin/bash

# this script need to be run on the board rather than the client machine.
WNUM=10000
RNUM=90000

fname=$1
resfile=$fname
# resdir=/tmp/eva_sqlite
# resfile=$resdir/res.tmp.$fname
# rm -rf $resfile
# mkdir -p $resdir

# sqlite_bench="taskset -c 2,3,4,5 /usr/bin/sqlite-bench"


# function run_test() {
# 	idx=$1
# 	cd /tmp;
# 	echo "<------------iter $idx ----------------->" | tee -a $resfile

# 	$sqlite_bench --num=$WNUM --benchmarks=fillseq 2>&1 \
# 	| grep -E "*fillseq*" | tee -a $resfile
	
# 	$sqlite_bench --num=$RNUM --benchmarks=readrandom 2>&1 \
# 	| grep -E "*readrandom*" | tee -a $resfile
# }


# ITER=10
# for i in $(seq 1 $ITER); do
# 	run_test $i
# done

# report
echo "fname: $resfile"
all_write_delay=0
write_count=0
all_read_delay=0
read_count=0

while IFS= read -r line; do
	echo "this line: $line"
	if [[ "$line" == *"fillseq"* ]]; then
		per_write_delay=$(echo "$line" | awk '{print $3}')
		all_write_delay=$(bc <<< "$all_write_delay + $per_write_delay")
		write_count=$((write_count + 1))
	elif [[ "$line" == *"readrandom"* ]]; then
		per_read_delay=$(echo "$line" | awk '{print $3}')
		all_read_delay=$(bc <<< "$all_read_delay + $per_read_delay")
		read_count=$((write_count + 1))
	fi 
done < $resfile

avg_write_delay=$(bc <<< "scale=2; $all_write_delay / $write_count")
avg_read_delay=$(bc <<< "scale=2; $all_read_delay / $read_count")

avg_write_time=$(bc <<< "scale=2; $WNUM * $avg_write_delay / 1000000")
avg_read_time=$(bc <<< "scale=2; $RNUM * $avg_read_delay / 1000000")
echo -e "\nAvg write_delay: $avg_write_delay. us/op" | tee -a $resfile
echo -e "Avg read_delay: $avg_read_delay. us/op" | tee -a $resfile
echo -e "Avg write_time: $avg_write_time s. " | tee -a $resfile
echo -e "Avg read_time: $avg_read_time s. " | tee -a $resfile
echo -e "Avg whole_time: $(bc <<< "scale=2; $avg_write_time + $avg_read_time") s." | tee -a $resfile
