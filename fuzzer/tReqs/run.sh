#!/bin/bash

function rand(){
    min=$1
    max=$(($2-$min+1))
    num=$(date +%s%N)
    echo $(($num%$max+$min))
}


if [ -z "${PRE_LOGIN_FILE}" ]
then
      echo "NO PRE LOGIN FILE!"
else
      service cron start
      (crontab -l 2>/dev/null; echo "* * * * * python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT} > /tmp/crontab_log.log ") | crontab -
      python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT}
fi

while true :
do
   echo $rnd
   rnd=$(rand 1 1000)
   timeout 5 python3 main.py -i -c $FUZZER_FILE -s $rnd
done> /t-reqs/code/logs/logs.txt
