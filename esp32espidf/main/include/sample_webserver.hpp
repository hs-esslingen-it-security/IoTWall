#ifndef __SAMPLE_WEBSERVER_H__
#define __SAMPLE_WEBSERVER_H__

#include <esp_https_server.h>
#include <stdlib.h>

/**
 * A web server that could be a configuration API or an API to fetch measurements in a real IoT application.
 */
class SampleWebserver {
    public:
        SampleWebserver();
        ~SampleWebserver();

        static void start(
            const char *ip,
            const uint16_t port = 8000,
            const uint16_t ctrl_port = 32770,
            const uint8_t* servercert_pem = nullptr,
            const size_t servercert_len = 0,
            const uint8_t* prvtkey_pem = nullptr,
            const size_t prvtkey_len = 0
        );
        static void stop();

    private:
        static const char TAG[];
    
        static httpd_handle_t server;
        static esp_err_t get_index_handler(httpd_req_t *req);

        static constexpr httpd_uri_t uri_get_index = {
            .uri      = "/",
            .method   = HTTP_GET,
            .handler  = SampleWebserver::get_index_handler,
            .user_ctx = NULL
        };
};

#endif
