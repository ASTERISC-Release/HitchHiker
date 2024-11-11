#!/bin/bash

rm -rf /tmp/emp_nginx
mkdir /tmp/emp_nginx

IP="192.168.2.2:8090"
FILE="data/file-4kb"
nginx_bench=ab


reqs=1000
conc=32


function run_test(){
	idx=$1
	ab -n $reqs -c $conc $IP/$FILE 2>&1\
	       | grep -E 'Time taken for tests|Requests per|Time per' \
       	       | tee /tmp/emp_nginx/res.$idx    
	echo "sleep for a while~"
	sleep 1
}

for i in 0 1 2 3 4; do
	run_test $i
done
