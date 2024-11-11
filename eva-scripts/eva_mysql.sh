#!/bin/bash

resdir=/tmp/eva_mysql
rm -rf $resdir
mkdir -p $resdir
resfile=$resdir/res.tmp

IP=192.168.3.2
PORT=3306
TABLE_SIZE=10000
MYSQL_USER="mysql"
THREADS=64
TRANSACTIONS=10000
TIME_LIM=100


function run_test() {
    idx=$1
	cd /tmp;
    echo "<-------------------- iter $idx ---------------------->" | tee -a $resfile
    
    sysbench oltp_read_write --db-driver=mysql --mysql-host=$IP \
            --mysql-port=$PORT --mysql-user=mysql --mysql-password='' \
            --mysql-db=testdb --tables=10 --table-size=$TABLE_SIZE prepare 2>&1 > /dev/null

    sysbench oltp_read_write --db-driver=mysql --mysql-host=$IP \
            --mysql-port=$PORT --mysql-user=mysql --mysql-password='' \
            --mysql-db=testdb --tables=10 --table-size=$TABLE_SIZE \
            --threads=$THREADS --events=$TRANSACTIONS --time=$TIME_LIM \
            --report-interval=10 run \
            | grep -E 'thds|queries|transactions|total time|total number of events' \
            | tee -a $resfile

    sysbench oltp_read_write --db-driver=mysql --mysql-host=$IP \
            --mysql-port=$PORT --mysql-user=mysql --mysql-password='' \
            --mysql-db=testdb --tables=10 --table-size=$TABLE_SIZE cleanup 2>&1 > /dev/null
}

ITER=5
for i in $(seq 1 $ITER); do
	run_test $i
done

#generate report
alliter_time=0
alliter_ops=0
time_count=0
ops_count=0
while IFS= read -r line; do
	if [[ "$line" == *"total time"* ]]; then
		# ext time
        per_time=$(echo "$line" | awk '{print $3}' | sed 's/[^0-9.]//g')
		alliter_time=$(bc <<< "$alliter_time + $per_time")
		time_count=$((time_count + 1))
	elif [[ "$line" == *"queries:"* ]]; then
        per_ops=$(echo "$line" | awk '{print $3}' | sed 's/[^0-9.]//g')
        alliter_ops=$(bc <<< "$alliter_ops + $per_ops")
        ops_count=$((ops_count + 1))
    fi
done < $resfile

avg_time=$(bc <<< "scale=2; $alliter_time / $time_count")
avg_ops=$(bc <<< "scale=2; $alliter_ops / $ops_count")

echo -e "\nAvg time: $avg_time s; Avg ops: $avg_ops ops/s." | tee -a $resfile
