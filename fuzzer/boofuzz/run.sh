#!/bin/bash

if [ -z "${PRE_LOGIN_FILE}" ]
then
      echo "NO PRE LOGIN FILE!"
else
      service cron start
      (crontab -l 2>/dev/null; echo "* * * * * python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT} > /tmp/crontab_log.log ") | crontab -
      
      python3 ${PRE_LOGIN_FILE} ${FUZZ_IP} ${FUZZ_PORT}
fi

python3 PDFuzzerGen.py generate_by_seed -ip ${FUZZ_IP} -port ${FUZZ_PORT} -policy ${FUZZ_POLICY} ${SEED_FILE}

python3 templates_created/1/fuzz_template_fuzz.py