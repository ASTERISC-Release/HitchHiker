#!/bin/bash

resdir=/tmp/emp_apache2
rm -rf $resdir
mkdir $resdir

IP="192.168.2.2:8180"
FILE="file-4kb"
apache_bench=ab

reqs=10000
conc=32


function run_test(){
	idx=$1
	$apache_bench -n $reqs -c $conc $IP/$FILE 2>&1 \
	       | grep -E 'Time taken for tests|Requests per' \
       	       | tee $resdir/res.$idx    
	echo "sleep for a while~"
	sleep 8
}

for i in 0 1 2 3 4; do
	run_test $i
done
