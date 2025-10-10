set termopt enhanced
set datafile separator ','
set xlabel 'Round'
set ylabel 'Duration (ms)'

set term svg size 800,600 background "#FFFFFF"

plot filename using 1:2 with lines lc rgb "#A0DD0000" title 'Sailfish'
