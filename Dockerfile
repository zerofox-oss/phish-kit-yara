FROM debian

WORKDIR /app
RUN apt-get -y update
RUN apt-get clean -y
RUN apt-get install git automake libtool make gcc wget g++ pkg-config libprotoc-dev libprotobuf-dev protobuf-compiler libssl-dev -y

RUN wget https://github.com/VirusTotal/yara/archive/v4.0.0.tar.gz -O yara.tar.gz
RUN tar -xzvf yara.tar.gz

RUN wget https://github.com/protobuf-c/protobuf-c/releases/download/v1.3.3/protobuf-c-1.3.3.tar.gz
RUN tar -xzvf protobuf-c-1.3.3.tar.gz
RUN cd protobuf-c-1.3.3 && ./configure && make && make install
RUN wget https://github.com/akheron/jansson/archive/v2.12.tar.gz -O jansson-2.12.tar.gz
RUN tar -xzvf jansson-2.12.tar.gz
RUN cd jansson-2.12 && autoreconf -fi && ./configure && make && make install

COPY ./libyara/miniz.c yara-4.0.0/libyara/miniz.c
COPY ./libyara/include/yara/miniz.h yara-4.0.0/libyara/include/yara/miniz.h
COPY ./libyara/modules/phishkit.c yara-4.0.0/libyara/modules/phishkit.c
COPY ./libyara/modules/module_list yara-4.0.0/libyara/modules/module_list
COPY ./libyara/Makefile.am yara-4.0.0/libyara/Makefile.am
RUN cd yara-4.0.0 && ./bootstrap.sh && ./configure --enable-cuckoo --with-crypto && make && make install && ldconfig

RUN mkdir /yara
RUN mkdir /yara/rules
RUN mkdir /yara/files
WORKDIR /yara