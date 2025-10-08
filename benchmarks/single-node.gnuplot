set termopt enhanced
set datafile separator ','
set xlabel 'Round'
set ylabel 'Duration (ms)'
set title 'Duration since Sailfish round start'

set term svg size 800,600 background "#FFFFFF"

plot filename using 1:2 with lines lc rgb "#C0DD0000" title 'Consensus',\
     filename using 1:3 with lines lc rgb "#C000DD00" title 'Sequenced',\
     filename using 1:4 with lines lc rgb "#C00000DD" title 'Certified', #filename using 1:5 with lines lc rgb "#C0000000" title 'Verified'
