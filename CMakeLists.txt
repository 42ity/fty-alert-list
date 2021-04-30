cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

##############################################################################################################

project(fty-alert-list VERSION 1.0.0)

########################################################################################################################

find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR})

########################################################################################################################

add_subdirectory(lib)
add_subdirectory(agent)

## agent configuration
## https://cmake.org/cmake/help/v3.0/module/GNUInstallDirs.html

set(AGENT_USER "bios")
# var/lib/fty/
set(AGENT_VAR_DIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/fty/${PROJECT_NAME}")

## .conf file -> lib/tmpfiles.d/
configure_file("${PROJECT_SOURCE_DIR}/resources/${PROJECT_NAME}.conf.in" "${PROJECT_BINARY_DIR}/resources/${PROJECT_NAME}.conf" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/${PROJECT_NAME}.conf" DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d/")

# service -> lib/systemd/system
configure_file("${PROJECT_SOURCE_DIR}/resources/${PROJECT_NAME}.service.in" "${PROJECT_BINARY_DIR}/resources/${PROJECT_NAME}.service" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/resources/${PROJECT_NAME}.service" DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/)
