cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

########################################################################################################################

etn_target(static ${PROJECT_NAME}-lib
    SOURCES
        src/alerts_utils.cc
        src/alerts_utils.h
        src/fty_alert_list_server.cc
        src/fty_alert_list_server.h
    USES_PRIVATE
        czmq
        mlm
        libzmq
        fty_proto
        fty_common
        fty_common_logging
    PRIVATE
)

########################################################################################################################

etn_test_target(${PROJECT_NAME}-lib
    CONFIGS
        tests/selftest-ro/*
    SOURCES
        tests/alert_list_server.cpp
        tests/alert_utils.cpp
        tests/main.cpp
    PREPROCESSOR
        -DCATCH_CONFIG_FAST_COMPILE
    SUBDIR
        tests
)

########################################################################################################################
