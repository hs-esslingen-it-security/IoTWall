cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# SET(SDKCONFIG "sdkconfig.debug")
SET(SDKCONFIG "sdkconfig.production")

# set(CMAKE_CXX_STANDARD 17)
# target_compile_options(${COMPONENT_LIB} PUBLIC -std=gnu++20)

# Use different sdkconfig per build environment defined in platformio.ini
# A dedicated sdkconfig for a build environment can be defined by naming it sdkconfig.default.<env_name>
# https://github.com/platformio/platform-espressif32/issues/638
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SDKCONFIG}.defaults")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sdkconfig.defaults")
        set(SDKCONFIG_DEFAULTS "sdkconfig.defaults;${SDKCONFIG}.defaults")
    else()
        set(SDKCONFIG_DEFAULTS "${SDKCONFIG}.defaults")
    endif()
    message(STATUS "Using defaults: ${SDKCONFIG_DEFAULTS}")
endif()

# ESPIDF
add_compile_definitions(ESP32_ESPIDF)
# add_compile_definitions(ESP_IDF_LWIP_HOOK_FILENAME="lwip_hooks.h")

# set(DESP_IDF_LWIP_HOOK_FILENAME "lwip_hooks.h")
# set(DESP32_ESPIDF)

project(ESP32Firewall)

# lwIP options
idf_component_get_property(lwip lwip COMPONENT_LIB)
target_compile_options(${lwip} PRIVATE "-I${PROJECT_DIR}/main/include")
target_compile_definitions(${lwip} PRIVATE ESP_IDF_LWIP_HOOK_FILENAME="lwip_hooks.h")
