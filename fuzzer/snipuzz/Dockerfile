FROM ubuntu:22.04

ADD sources.list /etc/apt/

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && \
    apt-get install -y git python3 python3-pip python3-pexpect unzip wget tar sudo vim locales build-essential cron


RUN pip -V && \
    python3 -m pip install --upgrade pip && \
    python3 -m pip install http_parser textdistance xmltodict requests pandas scipy

ARG FUZZ_SEED

ENV FUZZ_IP=${FUZZ_IP}
ENV FUZZ_PORT=${FUZZ_PORT}
ENV FUZZ_SEED=${FUZZ_SEED}
ENV PRE_LOGIN_FILE=${PRE_LOGIN_FILE}

RUN mkdir /snipuzz && mkdir /snipuzz/utils mkdir /snipuzz/updated_seed
ADD utils/ /snipuzz/utils/
ADD updated_seed/ /snipuzz/updated_seed/
ADD Snipuzz.py /snipuzz
ADD run.sh /snipuzz
WORKDIR /snipuzz

RUN chmod +x run.sh

ENTRYPOINT ./run.sh
