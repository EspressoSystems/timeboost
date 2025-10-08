set termopt enhanced
set datafile separator ','
set xlabel 'Round'
set ylabel 'Duration (ms)'
set title 'Duration between successive rounds (10 nodes)'

set term svg size 800,600 background "#FFFFFF"

plot filename using 1:2  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:3  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:4  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:5  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:6  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:7  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:8  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:9  with lines lc rgb "#E00000FF" notitle,\
     filename using 1:10 with lines lc rgb "#E00000FF" notitle,\
     filename using 1:11 with lines lc rgb "#E00000FF" notitle
