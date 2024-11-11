#!/bin/sh

# this script need to be run on the board rather than the client machine.
ITER=1
NUM=10000
rm -rf /tmp/sqlite
mkdir -p /tmp/sqlite
sqlite_bench=/usr/bin/sqlite-bench


function run_test() {
	test=$1
	idx=$2
	cd /tmp;
	time $sqlite_bench --num=$NUM --benchmarks=$test 2>&1 \
			| grep -E "micro|real" | tee /tmp/sqlite/res.$idx.$test
}

for test in fillseq readrandom; do
	for i in 0 1 2 3 4; do
		run_test $test $i
	done
done


# generate report
