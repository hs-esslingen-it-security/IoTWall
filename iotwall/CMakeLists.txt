cmake_minimum_required(VERSION 3.16)

set(srcs
    "src/iotwall_api.cpp"
    "src/firewall.cpp"
    "src/rules_dto.cpp"
    "src/storage.cpp"
    "src/utils.cpp"
)
idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "priv_include"
    REQUIRES nvs_flash esp_http_server esp_https_server esp-tls json
)
