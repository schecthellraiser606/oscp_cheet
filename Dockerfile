FROM ubuntu:20.04

RUN apt update && apt upgrade -y &&\
    apt install build-essential -y

WORKDIR /work