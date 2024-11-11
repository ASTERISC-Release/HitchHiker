#!/bin/sh

TIME="/usr/bin/time -f '%e'"

NUMS=10

total=0

# every time
for i in $(seq 1 $NUMS); do
    out=$($TIME taskset -c 2,3,4,5 /data/pidloop 2>&1)
    sec=$(echo $out | awk '{print $1}' | sed 's/[^0-9.]//g')
    total=$(echo "$total + $sec" | bc)
    echo "Run $i time (seconds): $sec"
done

# ave report
avg_time=$(echo "scale=3; $total / $NUMS" | bc)
echo "Avg (seconds): $avg_time"
