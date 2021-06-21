cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

########################################################################################################################

etn_target(exe ${PROJECT_NAME}
    SOURCES
        src/fty-alert-list.cc
    INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib/src
    USES_PRIVATE
        ${PROJECT_NAME}-lib
        libzmq
)

########################################################################################################################

etn_target(exe generate_alert
    SOURCES
        src/generate_alert.cc
    USES
        czmq
        mlm
        fty_proto
        fty_common_logging
)

########################################################################################################################

etn_target(exe fty-alert-list-convert
    SOURCES
        src/fty-alert-list-convert.cc
        src/bios_proto.cc
        src/bios_proto.h
    USES
        czmq
        fty_proto
        fty_common_logging
)

########################################################################################################################
