#!/bin/bash

LOGFILE="test.log"

for size in "200" "400" "600" "800" "1000" "1200" "1400"
do
	echo "Start $size test" >> $LOGFILE
	date >> $LOGFILE 
	./pktgen -s 10.0.0.10 -p 1232 -t 12 -n 3 -b $size -m 16
	echo "End $size test" >> $LOGFILE 
	date >> $LOGFILE 
	sleep 300
done
