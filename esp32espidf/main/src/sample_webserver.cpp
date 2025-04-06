#include "sample_webserver.hpp"

#include <esp_log.h>

const char SampleWebserver::TAG[] = "web_server";
httpd_handle_t SampleWebserver::server;

constexpr httpd_uri_t SampleWebserver::uri_get_index;

SampleWebserver::SampleWebserver() {
    
}

SampleWebserver::~SampleWebserver() {
    
}

void SampleWebserver::start(
    const char *ip,
    const uint16_t port,
    const uint16_t ctrl_port,
    const uint8_t* servercert_pem,
    const size_t servercert_len,
    const uint8_t* prvtkey_pem,
    const size_t prvtkey_len
) {
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.port_secure = port;
    config.cacert_pem = servercert_pem;
    config.cacert_len = servercert_len;
    config.prvtkey_pem = prvtkey_pem;
    config.prvtkey_len = prvtkey_len;

    config.httpd.ctrl_port = ctrl_port;
    config.httpd.max_uri_handlers = 10;
    config.httpd.uri_match_fn = httpd_uri_match_wildcard; // allow use of * in uri for delete and put

    esp_err_t http_res = httpd_ssl_start(&server, &config);
    
    
    if (http_res != ESP_OK) {
        ESP_LOGE(TAG, "Error starting web server");
        return;
    }
    ESP_LOGI(TAG, "Web server started on port %u", port);

    httpd_register_uri_handler(server, &SampleWebserver::uri_get_index);
}

void SampleWebserver::stop() {
    ESP_LOGI(TAG, "Stopping web server");
    httpd_stop(server);
}

esp_err_t SampleWebserver::get_index_handler(httpd_req_t *req)
{
    char json[] = "{\"foo\": \"bar\"}";

    httpd_resp_set_type(req, HTTPD_TYPE_JSON);
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}
