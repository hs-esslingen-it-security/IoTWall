#ifndef API_HPP
#define API_HPP


#include <esp_http_server.h>
#include <esp_https_server.h>
#include <string.h>
#include <stdlib.h>
#include <esp_log.h>
#include <esp_err.h>
#include <esp_tls_crypto.h>
#include <cJSON.h>

#include "config.hpp"
#include "firewall.hpp"
#include "utils.hpp"


namespace fw
{
    /**
     * @brief The API to create, edit or remove Firewall rules
     */
    class API
    {
    public:
        API(
            Firewall *,
            const char *ip,
            const char *username,
            const char *password,
            const uint16_t port = 8080,
            const uint16_t ctrl_port = 32768,
            const uint8_t* servercert_pem = nullptr,
            const size_t servercert_len = 0,
            const uint8_t* prvtkey_pem = nullptr,
            const size_t prvtkey_len = 0
        );

        /**
         * @brief Destroy the API object
         *
         */
        ~API();

        static Firewall *firewall;
        static api_endpoint_t *endpoint_head;
        static char TAG[];
        static credential_t credentials;

    private:
        httpd_handle_t server = NULL;

        char *api_ip;
        uint16_t api_port;

        static uint8_t* servercert_pem ;
        static size_t servercert_len;
        static uint8_t* prvtkey_pem;
        static size_t prvtkey_len;

        // Base URL of the API, e.g., http://0.0.0.0:8080/api
        char *base_url;

        /**
         * String to store error messages.
         * In case of an error in a subfunction, it is stored here.
         */
        static char error_msg[100];

        static esp_err_t setup_auth(const char *username, const char *password);

        /**
         * @brief check if request to API can proceed or needs to stop
         *
         * @return auth_t
         */
        static esp_err_t check_auth(httpd_req_t *req);

        // Authentication

        typedef struct {
            char *username;
            char *password;
        } basic_auth_info_t;
        
        // static httpd_uri_t basic_auth = {
        //     .uri       = "/basic_auth",
        //     .method    = HTTP_GET,
        //     .handler   = basic_auth_get_handler,
        // };

        static void httpd_register_basic_auth(httpd_handle_t server);

        static char *http_auth_basic(const char *username, const char *password);

        /** Parses JSON from the string received from an HTTP request */
        static int parse_json(cJSON *&json_buf, char *buf);

        static int parse_credentials_json(cJSON *json, char **username, char **password);

        //API endpoints
        static esp_err_t get_endpoint_list_handler(httpd_req_t *req);

        /* URI handler structure for GET /uri */
        static constexpr httpd_uri_t uri_get_endpoint_list = {
            .uri      = "/api",
            .method   = HTTP_GET,
            .handler  = API::get_endpoint_list_handler,
            .user_ctx = NULL
        };

        static esp_err_t get_firewall_rules_handler(httpd_req_t *req);

        /* URI handler structure for GET /uri */
        static constexpr httpd_uri_t uri_get_firewall_rules = {
            .uri      = "/api/firewall/rules",
            .method   = HTTP_GET,
            .handler  = API::get_firewall_rules_handler,
            .user_ctx = NULL
        };

        static esp_err_t post_firewall_rules_handler(httpd_req_t *req);

        static constexpr httpd_uri_t uri_post_firewall_rules = {
            .uri      = "/api/firewall/rules",
            .method   = HTTP_POST,
            .handler  = API::post_firewall_rules_handler,
            .user_ctx = NULL
        };

        static esp_err_t put_firewall_rules_handler(httpd_req_t *req);

        static constexpr httpd_uri_t uri_put_firewall_rules = {
            .uri      = "/api/firewall/rules/*",
            .method   = HTTP_PUT,
            .handler  = API::put_firewall_rules_handler,
            .user_ctx = NULL
        };

        static esp_err_t delete_firewall_rules_handler(httpd_req_t *req);

        static constexpr httpd_uri_t uri_delete_firewall_rules = {
            .uri      = "/api/firewall/rules/*",
            .method   = HTTP_DELETE,
            .handler  = API::delete_firewall_rules_handler,
            .user_ctx = NULL
        };

        static esp_err_t put_credential_handler(httpd_req_t *req);

        static constexpr httpd_uri_t uri_put_credential = {
            .uri      = "/api/credentials",
            .method   = HTTP_PUT,
            .handler  = API::put_credential_handler,
            .user_ctx = NULL
        };

        // JSON

        void add_endpoint_to_list(const char *uri, const char *method, const char *description);

        /**
         * @brief construct array of all endpoints as json object
         *
         * @param api_ptr
         * @return char*
         */
        static char *construct_json_api();

        /**
         * @brief construct an API endpoint as json object
         *
         * @param api_ptr
         * @return String
         */
        static cJSON *construct_json_api_endpoint(api_endpoint_t *api_ptr);

        /**
         * @brief construct array of all firewall rules as json object
         *
         * @return char*
         */
        static char *construct_json_firewall();

        /**
         * @brief construct a firewall rule as json object
         *
         * @param rule_ptr
         * @return String
         */
        static cJSON *construct_json_firewall_rule(const firewall_rule_t &rule);
    };


}


#endif
