set termopt enhanced
set datafile separator ','
set xlabel 'Round'
set ylabel 'Duration (ms)'

set term svg size 800,600 background "#FFFFFF"

plot filename using 1:2 with lines lc rgb "#A000DD00" title 'Round start',\
     filename using 1:3 with lines lc rgb "#A0DDDD00" title 'RBC leader info',\
     filename using 1:4 with lines lc rgb "#A00000DD" title 'Sailfish commit',\
     filename using 1:5 with lines lc rgb "#A0DD0000" title 'Decrypt',\
     filename using 1:6 with lines lc rgb "#A000DDDD" title 'Certify',\
     filename using 1:7 with lines lc rgb "#A0DD00DD" title 'Sailfish commit ⟶ Certify'
