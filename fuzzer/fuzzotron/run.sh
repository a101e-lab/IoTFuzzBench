#!/bin/bash

if [ -z "${PRE_LOGIN_FILE}" ]
then
      echo "NO PRE LOGIN FILE!"
else
      service cron start
      (crontab -l 2>/dev/null; echo "* * * * * python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT} > /tmp/crontab_log.log ") | crontab -
      python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT}
fi

./fuzzotron --radamsa --directory testcases -h ${FUZZ_IP} -p ${FUZZ_PORT} -P tcp -o crashes