FROM alpine:3.13 

RUN apk add --no-cache build-base=0.5-r2 pcre2-dev=10.36-r0 git=2.30.2-r0 cmake=3.18.4-r1 libssh-dev=0.9.5-r0 openssl-dev=1.1.1n-r0 openssl=1.1.1n-r0 bash=5.1.16-r0

ARG LIBYANG_VERSION
ARG SYSREPO_VERSION
ARG LIBNETCONF2_VERSION
ARG NETOPEER2_VERSION

RUN echo "/lib:/usr/local/lib:/usr/lib:/usr/local/lib64" > /etc/ld-musl-x86_64.path

#Build libyang
WORKDIR /
RUN git clone https://github.com/CESNET/libyang.git
WORKDIR /libyang
RUN git checkout $LIBYANG_VERSION && mkdir build
WORKDIR /libyang/build
RUN cmake -D CMAKE_BUILD_TYPE:String="Release" .. && \
    make && \
    make install

#Build sysrepo
WORKDIR /
RUN git clone https://github.com/sysrepo/sysrepo.git
WORKDIR /sysrepo
RUN git checkout $SYSREPO_VERSION && mkdir build
WORKDIR /sysrepo/build
RUN cmake -D CMAKE_BUILD_TYPE:String="Release" .. && \
    make && \
    make install

#Build libnetconf2
WORKDIR /
RUN git clone https://github.com/CESNET/libnetconf2.git
WORKDIR /libnetconf2
RUN git checkout $LIBNETCONF2_VERSION && mkdir build
WORKDIR /libnetconf2/build
RUN cmake -D CMAKE_BUILD_TYPE:String="Release" .. && \
    make && \
    make install

#Build netopeer2
WORKDIR /
RUN git clone https://github.com/CESNET/netopeer2.git
WORKDIR /netopeer2
RUN git checkout $NETOPEER2_VERSION && mkdir build
WORKDIR /netopeer2/build
RUN cmake -D CMAKE_BUILD_TYPE:String="Release" .. && \
    make && \
    make install

COPY ./plugin.c /app/plugin.c
WORKDIR /app
RUN gcc plugin.c -o plugin -lsysrepo -lyang

COPY ./yang-files /yang
RUN for f in /yang/*.yang; do sysrepoctl -i "$f" -s /yang -p 664 -v3; done