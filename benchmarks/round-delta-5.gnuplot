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
