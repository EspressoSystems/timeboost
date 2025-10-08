set termopt enhanced
set datafile separator ','
set xlabel 'Round'
set ylabel 'Duration (ms)'
set title 'Duration between successive rounds (5 nodes)'

set term svg size 800,600 background "#FFFFFF"

plot filename using 1:2 with lines lc rgb "#E00000FF" notitle,\
     filename using 1:3 with lines lc rgb "#E00000FF" notitle,\
     filename using 1:4 with lines lc rgb "#E00000FF" notitle,\
     filename using 1:5 with lines lc rgb "#E00000FF" notitle,\
     filename using 1:6 with lines lc rgb "#E00000FF" notitle
