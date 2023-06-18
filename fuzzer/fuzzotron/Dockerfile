FROM ubuntu:22.04

ADD sources.list /etc/apt/

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev libpcre3-dev git python3 python3-pip python3-pexpect unzip wget tar sudo vim locales build-essential cron net-tools gcc make


RUN git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make && sudo make install
RUN git clone https://github.com/denandz/fuzzotron.git && cd fuzzotron && make


ARG FUZZ_SEED

ENV FUZZ_IP=${FUZZ_IP}
ENV FUZZ_PORT=${FUZZ_PORT}
ENV FUZZ_SEED=${FUZZ_SEED}
ENV LOG_DIR=${LOG_DIR}
ENV LOG_FILE=${LOG_FILE}
ENV PRE_LOGIN_FILE=${PRE_LOGIN_FILE}

RUN cd /fuzzotron && mkdir testcases
ADD updated_seed/ /fuzzotron/testcases/
ADD run.sh /fuzzotron
WORKDIR /fuzzotron

RUN chmod +x run.sh

ENTRYPOINT ./run.sh


# RUN pip -V && \
#     python3 -m pip install --upgrade pip && \
#     python3 -m pip install http_parser textdistance xmltodict requests

# ARG FUZZ_SEED

# ENV FUZZ_IP=${FUZZ_IP}
# ENV FUZZ_PORT=${FUZZ_PORT}
# ENV FUZZ_SEED=${FUZZ_SEED}
# ENV LOG_DIR=${LOG_DIR}
# ENV LOG_FILE=${LOG_FILE}
# ENV PRE_LOGIN_FILE=${PRE_LOGIN_FILE}

# RUN mkdir /mslfuzzer && mkdir /mslfuzzer/utils mkdir /mslfuzzer/updated_seed
# ADD mslfuzzer.py /mslfuzzer
# ADD utils/ /mslfuzzer/utils/
# ADD updated_seed/ /mslfuzzer/updated_seed/
# ADD run.sh /mslfuzzer
# WORKDIR /mslfuzzer

# RUN chmod +x run.sh

# ENTRYPOINT ./run.sh
