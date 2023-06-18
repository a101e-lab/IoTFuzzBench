FROM ubuntu:20.04

ADD sources.list /etc/apt/

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && \
    apt-get install -y git python3 python3-pip python3-pexpect unzip wget tar sudo vim locales build-essential gcc make cron


RUN python3 -m pip install beautifulsoup4 boofuzz==0.2.1 http-parser==0.9.0 requests==2.25.1 scapy==2.4.4

RUN mkdir /pdfuzzergen && cd /usr/lib/x86_64-linux-gnu/ && ln -s -f libc.a liblibc.a

ENV SEED_FILE=${SEED_FILE}
ENV FUZZ_IP=${FUZZ_IP}
ENV FUZZ_PORT=${FUZZ_PORT}
ENV FUZZ_POLICY=${FUZZ_POLICY}
ENV PRE_LOGIN_FILE=${PRE_LOGIN_FILE}

ADD updated_seed/ /pdfuzzergen/updated_seed/
ADD util/ /pdfuzzergen/util/
ADD run.sh /pdfuzzergen
ADD PDFuzzerGen.py /pdfuzzergen
WORKDIR /pdfuzzergen

RUN chmod +x run.sh

ENTRYPOINT ./run.sh
