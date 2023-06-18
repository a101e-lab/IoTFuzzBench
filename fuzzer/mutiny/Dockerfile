FROM ubuntu:22.04

ADD sources.list /etc/apt/

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && \
    apt-get install -y git python3 python3-pip python3-pexpect unzip wget tar sudo vim locales build-essential gcc make cron

RUN git clone https://github.com/Cisco-Talos/mutiny-fuzzer.git && cd mutiny-fuzzer && tar zxvf radamsa-v0.6.tar.gz && cd radamsa-0.6 && make && make install
RUN mkdir /mutiny-fuzzer/log/ && mkdir /mutiny-fuzzer/updated_seed/

RUN pip -V && \
    python3 -m pip install --upgrade pip && \
    python3 -m pip install http_parser textdistance xmltodict requests

ARG FUZZER_FILE

ENV FUZZER_FILE=${FUZZER_FILE}
ENV FUZZ_IP=${FUZZ_IP}
ENV PRE_LOGIN_FILE=${PRE_LOGIN_FILE}
ENV FUZZ_PORT=${FUZZ_PORT}


ADD updated_seed/ /mutiny-fuzzer/updated_seed/
ADD run.sh /mutiny-fuzzer
WORKDIR /mutiny-fuzzer

# RUN mkdir /mslfuzzer && mkdir /mslfuzzer/utils mkdir /mslfuzzer/updated_seed
# ADD mslfuzzer.py /mslfuzzer
# ADD utils/ /mslfuzzer/utils/
# ADD updated_seed/ /mslfuzzer/updated_seed/
# ADD run.sh /mslfuzzer
# WORKDIR /mslfuzzer

RUN chmod +x run.sh

ENTRYPOINT ./run.sh
