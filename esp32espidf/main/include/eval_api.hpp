#ifndef __EVAL_API_H__
#define __EVAL_API_H__

#include "config.h"

#include <stdint.h>
#include <esp_http_server.h>
#include <cJSON.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// Error codes

#define EVAL_API_OK 0
#define EVAL_API_ERR 1
/** Tried to access nullptr */
#define EVAL_API_ERR_NULLPTR 2
/** Invalid user input */
#define EVAL_API_ERR_INPUT 3

class EvalApi
{
    public:
        EvalApi(
            const uint16_t port = 8082,
            const uint16_t ctrl_port = 32768
        );

        ~EvalApi();

        static esp_err_t post_restart_device_handler(httpd_req_t *req);

        // Restart device. Restart may take some time.
        static constexpr httpd_uri_t uri_post_restart_device = {
            .uri      = "/api/restart",
            .method   = HTTP_POST,
            .handler  = EvalApi::post_restart_device_handler,
            .user_ctx = NULL
        };

        static esp_err_t get_uptime_handler(httpd_req_t *req);

        // Get uptime of device in microseconds
        static constexpr httpd_uri_t uri_get_uptime = {
            .uri      = "/api/uptime",
            .method   = HTTP_GET,
            .handler  = EvalApi::get_uptime_handler,
            .user_ctx = NULL
        };

        static esp_err_t get_memory_use_handler(httpd_req_t *req);

        // Get memory use of device
        static constexpr httpd_uri_t uri_get_memory_use = {
            .uri      = "/api/memory",
            .method   = HTTP_GET,
            .handler  = EvalApi::get_memory_use_handler,
            .user_ctx = NULL
        };

#if PERFORMANCE_MEASUREMENTS_ENABLED
        static esp_err_t post_firewall_performance_measurements_status_handler(httpd_req_t *req);

        // Enable/disable firewall performance measurements
        static constexpr httpd_uri_t uri_post_firewall_performance_measurements_status = {
            .uri      = "/api/performance-measurements",
            .method   = HTTP_POST,
            .handler  = EvalApi::post_firewall_performance_measurements_status_handler,
            .user_ctx = NULL
        };

        static esp_err_t get_firewall_performance_measurements_results_handler(httpd_req_t *req);

        // Get firewall performance measurements results
        static constexpr httpd_uri_t uri_get_firewall_performance_measurements_results = {
            .uri      = "/api/performance-measurements/results",
            .method   = HTTP_GET,
            .handler  = EvalApi::get_firewall_performance_measurements_results_handler,
            .user_ctx = NULL
        };
#endif

    private:
        httpd_handle_t server;

        /**
         * String to store error messages.
         * In case of an error in a subfunction, it is stored here.
         */
        static char error_msg[100];

        /** Parses JSON from the string received from an HTTP request */
        static int parse_json(cJSON *&json_buf, char *buf);
};

#endif
