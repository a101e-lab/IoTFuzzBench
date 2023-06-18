#!/bin/bash

if [ -z "${PRE_LOGIN_FILE}" ]
then
      echo "NO PRE LOGIN FILE!"
else
      service cron start
      (crontab -l 2>/dev/null; echo "* * * * * python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT} > /tmp/crontab_log.log ") | crontab -
      python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT}
fi

echo ${FUZZ_IP}
echo ${FUZZ_PORT}
echo ${FUZZ_SEED}

python3 Snipuzz.py ${FUZZ_IP} ${FUZZ_PORT} ${FUZZ_SEED}