#!/bin/bash

fname=$1
resdir=/tmp/eva_apache2
resfile=$resdir/res.tmp.$fname
rm -rf $resfile
mkdir -p $resdir

IP="192.168.2.2:8180"
FILE="file-4kb"
apache_bench=ab

reqs=10000
conc=32


function run_test(){
	idx=$1
	echo "$($apache_bench -n $reqs -c $conc $IP/$FILE 2>&1)" \
	       | grep -E 'Time taken for tests|Requests per' \
       	       | tee -a $resfile
	echo "<------------- done iter $idx --------------->"
	
}

ITER=1
for i in $(seq 1 $ITER); do
	run_test $i
done

# # report
# all_time=0
# time_count=0
# all_reqs=0
# req_count=0

# while IFS= read -r line; do
# 	if [[ "$line" == *"Time taken for tests"* ]]; then
# 		per_time=$(echo "$line" | awk '{print $5}')
# 		all_time=$(bc <<< "$all_time + $per_time")
# 		time_count=$((time_count + 1))
# 	elif [[ "$line" == *"Requests per"* ]]; then
# 		per_reqs=$(echo "$line" | awk '{print $4}')
# 		all_reqs=$(bc <<< "$all_reqs + $per_reqs")
# 		req_count=$((req_count + 1))
# 	fi
# done < $resfile

# avg_time=$(bc <<< "scale=2; $all_time / $time_count")
# avg_reqs=$(bc <<< "scale=2; $all_reqs / $req_count")

# echo -e "\nAvg time: $avg_time. Avg req/s: $avg_reqs." | tee -a $resfile