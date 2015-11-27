#!/usr/bin/env bash

set -x

if [ $BUILD_TYPE == "default" ]; then
    mkdir tmp
    BUILD_PREFIX=$PWD/tmp

    CONFIG_OPTS=()
    CONFIG_OPTS+=("CFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("CXXFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
    CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")
    CONFIG_OPTS+=("--prefix=${BUILD_PREFIX}")

    # Clone and build dependencies
    git clone https://github.com/zeromq/libzmq libzmq
    ( cd libzmq && ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make check && make install ) || exit 1

    git clone https://github.com/zeromq/czmq czmq
    ( cd czmq && ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make check && make install ) || exit 1

    git clone https://github.com/zeromq/malamute malamute
    ( cd malamute && ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make check && make install ) || exit 1

    git clone https://stash.mbt.lab.etn.com/bios/libbiosproto biosproto
    ( cd biosproto && ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make check && make install ) || exit 1

    # Build and check this project
    ( ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make && make check && make memcheck && make install ) || exit 1
else
    cd ./builds/${BUILD_TYPE} && ./ci_build.sh
fi
