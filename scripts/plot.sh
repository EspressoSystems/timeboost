#!/usr/bin/env bash

dir=$(mktemp -p /tmp -d csv-XXXXX)
inputs=("$@")

for i in ${!inputs[@]}; do
    xan rename "delta-$i" -s delta "${inputs[$i]}" -o "$dir/0$i.csv"
done

xan cat columns $dir/*.csv | xan select 'round,delta-*' -o "$dir/data.csv"
gnuplot -e "filename=\"$dir/data.csv\"" times.gnuplot > times.pdf
xan stats -s "1:" -q "$dir/data.csv" | xan select mean,q1,median,q3,stddev | xan view -MR
