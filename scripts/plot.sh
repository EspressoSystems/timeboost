#!/usr/bin/env bash

dir=$(mktemp -p /tmp -d csv-XXXXX)
inputs=("$@")

cat > "$dir/times.gnuplot" <<END
set termopt enhanced
set datafile separator ','
set xlabel 'Round'
set ylabel 'Duration (ms)'
set title 'Round durations'

set term pdfcairo font "Monospace,9"

plot filename using 1:2 with lines lc rgb "#C0FF6E00" title 'Node_{0}',\
     filename using 1:3 with lines lc rgb "#C0505050" title 'Node_{1}',\
     filename using 1:4 with lines lc rgb "#C0009000" title 'Node_{2}',\
     filename using 1:5 with lines lc rgb "#C0FF0000" title 'Node_{3}',\
     filename using 1:6 with lines lc rgb "#C00000FF" title 'Node_{4}'
END

for i in ${!inputs[@]}; do
    xan rename "delta-$i" -s delta "${inputs[$i]}" -o "$dir/0$i.csv"
done

xan cat columns $dir/*.csv | xan select 'round,delta-*' -o "$dir/data.csv"
gnuplot -e "filename=\"$dir/data.csv\"" "$dir/times.gnuplot" > times.pdf
xan stats -s "1:" -q "$dir/data.csv" | xan select mean,q1,median,q3,stddev | xan view -MR
