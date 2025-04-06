#include "iotwall_api.hpp"

#include <freertos/task.h>
#include "rules_dto.hpp"

namespace fw
{
    Firewall *API::firewall = nullptr;
    api_endpoint_t *API::endpoint_head = NULL;
    char API::TAG[] = "firewall_api";
    credential_t API::credentials = {"", ""};

    char API::error_msg[100] = "";

    constexpr httpd_uri_t API::uri_get_endpoint_list;
    constexpr httpd_uri_t API::uri_get_firewall_rules;
    constexpr httpd_uri_t API::uri_post_firewall_rules;
    constexpr httpd_uri_t API::uri_put_firewall_rules;
    constexpr httpd_uri_t API::uri_delete_firewall_rules;
    constexpr httpd_uri_t API::uri_put_credential;

    API::API(
        Firewall *fw_ptr,
        const char *ip,
        const char *username,
        const char *password,
        const uint16_t port,
        const uint16_t ctrl_port,
        const uint8_t* servercert_pem,
        const size_t servercert_len,
        const uint8_t* prvtkey_pem,
        const size_t prvtkey_len
    )
    {
        // TODO: prevent that we assign the fw_ptr to a static variable
        firewall = fw_ptr;

        api_ip = new char[strlen(ip) + 1];
        strcpy(api_ip, ip);

        api_port = port;

        // Space for IP, port, colon, \0
        const size_t buf_len = strlen(api_ip) + 1 + 5 + 1;
        base_url = new char[buf_len];
        snprintf(base_url, buf_len, "%s:%u", api_ip, api_port);

        if (firewall->get_credentials_set() == 0)
        {
            ESP_LOGI(TAG, "New Credentials");
            if (setup_auth(username, password) == ESP_ERR_INVALID_SIZE)
                ESP_LOGW(TAG, "Invalid Credential Size");
        }
        else
        {
            ESP_LOGI(TAG, "Old Credentials");
            credential_t *credential_ptr = firewall->get_credentials_of_firewall();
            setup_auth(credential_ptr->username, credential_ptr->password);
        }

#if FW_API_HTTPS == 1
        httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
        config.port_secure = port;
        config.cacert_pem = servercert_pem;
        config.cacert_len = servercert_len;
        config.prvtkey_pem = prvtkey_pem;
        config.prvtkey_len = prvtkey_len;

        config.httpd.ctrl_port = ctrl_port;
        config.httpd.max_uri_handlers = 10;
        config.httpd.uri_match_fn = httpd_uri_match_wildcard; // allow use of * in uri for delete and put

        esp_err_t http_res = httpd_ssl_start(&this->server, &config);
#else
        httpd_config_t config = HTTPD_DEFAULT_CONFIG();

        config.server_port = port;
        config.ctrl_port = ctrl_port;
        config.max_uri_handlers = 10;
        config.uri_match_fn = httpd_uri_match_wildcard; // allow use of * in uri for delete and put

        esp_err_t http_res = httpd_start(&this->server, &config);
#endif
        

        if (http_res != ESP_OK) {
            ESP_LOGE(TAG, "Error starting FW API");
            return;
        }

        // ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
        httpd_register_uri_handler(server, &API::uri_get_endpoint_list);
        httpd_register_uri_handler(server, &API::uri_get_firewall_rules);
        httpd_register_uri_handler(server, &API::uri_post_firewall_rules);
        httpd_register_uri_handler(server, &API::uri_put_firewall_rules);
        httpd_register_uri_handler(server, &API::uri_delete_firewall_rules);
        httpd_register_uri_handler(server, &API::uri_put_credential);

        httpd_register_basic_auth(server);

        ESP_LOGI(TAG, "FW API started on port %u", port);

        // Add endpoints to api list
        add_endpoint_to_list("/api/firewall/rules", "GET", "Get all Firewall Rules");
        add_endpoint_to_list("/api/firewall/rules/<key>", "GET", "Get Firewall Rule by key");
        add_endpoint_to_list("/api/firewall/rules", "POST", "Create Firewall Rule");
        add_endpoint_to_list("/api/firewall/rules/<key>", "PUT", "Update Firewall Rule by key");
        add_endpoint_to_list("/api/firewall/rules/<key>", "DELETE", "Delete Firewall Rule by key");
        add_endpoint_to_list("/api/credentials", "PUT", "Update User Credentials");
    }

    API::~API()
    {
        httpd_stop(this->server);
        delete[] api_ip;
        delete[] base_url;

        ESP_LOGI(TAG, "FW API stopped");
    }

    esp_err_t API::setup_auth(const char *username, const char *password)
    {
        if (!username || *username == 0x00 || strlen(username) > CREDENTIALS_LENGTH)
        {
            ESP_LOGI(TAG, "Username too long or missing!");
            return ESP_ERR_INVALID_SIZE;
        }
        strlcpy(credentials.username, username, CREDENTIALS_LENGTH);
        if (!password || *password == 0x00 || strlen(password) > CREDENTIALS_LENGTH)
        {
            ESP_LOGI(TAG, "Password too long or missing!");
            return ESP_ERR_INVALID_SIZE;
        }
        strlcpy(credentials.password, password, CREDENTIALS_LENGTH);
        firewall->update_credentials_of_firewall(&credentials);



        return ESP_OK;
    }


    void API::add_endpoint_to_list(const char *uri, const char *method, const char *description)
    {
        api_endpoint_t *temp;
        char url[64] = "error";
        snprintf(url, sizeof(url), "%s%s", base_url, uri);

        api_endpoint_t *api_ptr = (api_endpoint_t *)malloc(sizeof(api_endpoint_t));
        snprintf(api_ptr->uri, sizeof(api_ptr->uri), "%s", url);
        snprintf(api_ptr->method, sizeof(api_ptr->method), "%s", method);
        snprintf(api_ptr->description, sizeof(api_ptr->description), "%s", description);

        if (endpoint_head == NULL)
        {
            endpoint_head = api_ptr;
            api_ptr->next = NULL;
            return;
        }
        temp = endpoint_head;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = api_ptr;
        api_ptr->next = NULL;
        return;
    }

    // Authentication
    void API::httpd_register_basic_auth(httpd_handle_t server)
    {
        // basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
        // if (basic_auth_info) {
        //     // basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        //     // basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        //     basic_auth.user_ctx = basic_auth_info;
        //     httpd_register_uri_handler(server, &basic_auth);
        // }
    }

    // TODO from link
    char *API::http_auth_basic(const char *username, const char *password)
    {
        int out;
        // +2 for : and \0
        int user_info_size = strlen(username) + strlen(password) + 2;
        char user_info[user_info_size];
        char *digest = NULL;
        size_t n = 0;
        snprintf(user_info, user_info_size, "%s:%s", username, password);
        esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));
        digest = (char *)calloc(1, 6 + n + 1);
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, (size_t *)&out, (const unsigned char *)user_info, strlen(user_info));
        return digest;
    }

    esp_err_t API::check_auth(httpd_req_t *req)
    {
        size_t buf_len = 0;
    
        buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
        if (buf_len > 1) {
            char buf[buf_len];
            if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
                char *auth_credentials = http_auth_basic(credentials.username, credentials.password);

                if (strncmp(auth_credentials, buf, buf_len)) 
                {
                    free(auth_credentials);
                    ESP_LOGE(TAG, "Not authenticated");
                    return ESP_FAIL;
                }
                else
                {
                    free(auth_credentials);
                    ESP_LOGI(TAG, "Authenticated!");
                    return ESP_OK;
                }
            } 
            else {
                return ESP_FAIL;
            }

        }

        return ESP_FAIL;
    }
    
    int API::parse_json(cJSON *&json_buf, char *buf)
    {

        const char *parse_error_ptr;
        json_buf = cJSON_ParseWithOpts(buf, &parse_error_ptr, true);

        if (json_buf == NULL)
        {
            if (parse_error_ptr != NULL)
            {
                snprintf(error_msg, 100, "Error parsing JSON. Error before: %s", parse_error_ptr);
                ESP_LOGE(TAG, "%s", error_msg);

                return FW_ERR_INPUT;
            }
            else
            {
                strlcpy(error_msg, "Error parsing JSON. No error location available.", 49);
                ESP_LOGE(TAG, "%s", error_msg);

                return FW_ERR_INPUT;
            }
        }

        ESP_LOGD(TAG, "JSON parsed successfully");
        return FW_OK;
    }

    // API Endpoints
    esp_err_t API::get_endpoint_list_handler(httpd_req_t *req)
    {
        char *json = construct_json_api();

        httpd_resp_set_type(req, HTTPD_TYPE_JSON);
        httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
        free(json);
        return ESP_OK;
    }


    esp_err_t API::get_firewall_rules_handler(httpd_req_t *req)
    {
        if (check_auth(req) == ESP_FAIL)
        {
            httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, NULL);
            return ESP_OK;
        }

        char *json = construct_json_firewall();

        ESP_LOGW(TAG, "%s", json);

        httpd_resp_set_type(req, HTTPD_TYPE_JSON);
        httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);

        free(json);

        return ESP_OK;
    }

    esp_err_t API::post_firewall_rules_handler(httpd_req_t *req)
    {
        if (check_auth(req) == ESP_FAIL)
        {
            httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, NULL);
            return ESP_OK;
        }

        char *buf = nullptr;
        cJSON *json = nullptr;

        // firewall_rule_t new_rule;
        // bool ip4 = false;

        size_t buf_len = req->content_len;

        if (buf_len == 0)
        {
            // Request has no body
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Rule(s) expected in request body");
            return ESP_OK;
        }
        
        buf = new char[buf_len + 1];
        int ret = httpd_req_recv(req, buf, buf_len);

        if (ret <= 0)
        {
            // Error receiving body
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                httpd_resp_send_408(req);
            }

            delete buf;
            return ESP_FAIL;
        }

        // Request body is available
        // Add \0
        buf[buf_len] = '\0';

        int parse_err = parse_json(json, buf);

        int dto_err = FW_OK;
        RulesDto rules_dto;
        if (parse_err == FW_OK)
        {
            rules_dto = RulesDto();
            dto_err = rules_dto.from_json(json, FW_MAX_RULES);
        }

        if (parse_err != FW_OK || dto_err != FW_OK)
        {
            if (parse_err == FW_ERR_INPUT)
            {
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, error_msg);
            }
            else if (dto_err == FW_ERR_INPUT)
            {
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, rules_dto.get_last_error());
            }
            else
            {
                // FW_ERR
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Internal Server Error");
            }

            delete buf;
            cJSON_Delete(json);
            return ESP_OK;
        }

        rules_request_t rules_request = rules_dto.get_parsed_request();

        ESP_LOGD(TAG, "Received %u rules to configure", rules_request.rule_count);

        for (uint8_t i = 0; i < rules_request.rule_count; i++)
        {
            ESP_LOGD(TAG, "Configuring rule %d", i);
            firewall->add_new_rule_to_firewall(rules_request.rules[i], 0);
        }

        // httpd_resp_send(req, construct_json_firewall_rule(&new_rule), HTTPD_RESP_USE_STRLEN);
        httpd_resp_send(req, "done", HTTPD_RESP_USE_STRLEN);
        delete buf;
        cJSON_Delete(json);
        return ESP_OK;
    }

    esp_err_t API::put_firewall_rules_handler(httpd_req_t *req)
    {
        if (check_auth(req) == ESP_FAIL)
        {
            httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, NULL);
            return ESP_OK;
        }

        // size_t uriLen = strlen(req->uri);
        // uint8_t ruleKey = atoi(req->uri + uriLen - 1);

        // TODO

        const char* resp = "Rule Updated";
        httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);

        return ESP_OK;
    }

    esp_err_t API::delete_firewall_rules_handler(httpd_req_t *req)
    {
        if (check_auth(req) == ESP_FAIL)
        {
            httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, NULL);
            return ESP_OK;
        }
        
        const char *rule_key_str = req->uri + strlen(uri_delete_firewall_rules.uri) - 1;

        if (strlen(rule_key_str) == 0)
        {
            // Request URI does not contain a rule key
            ESP_LOGD(TAG, "No rule key passed, deleting all rules");

            if (firewall->delete_all_rules_from_firewall() == SUCCESS)
            {
                const char* resp = "All rules deleted";
                httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
            }
            else
            {
                const char* resp = "No rules deleted";
                httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
            }
        } else
        {
            uint8_t rule_key = atoi(rule_key_str);

            if (firewall->delete_rule_from_firewall(rule_key) == SUCCESS)
            {
                const char* resp = "Rule Deleted";
                httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
            }
            else
            {
                const char* resp = "Not Deleted";
                httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
            }
        }

        return ESP_OK;
    }

    esp_err_t API::put_credential_handler(httpd_req_t *req)
    {
        if (check_auth(req) == ESP_FAIL)
        {
            httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, NULL);
            return ESP_OK;
        }

        char *buf = nullptr;
        cJSON *json = nullptr;

        // firewall_rule_t new_rule;
        // bool ip4 = false;

        size_t buf_len = req->content_len;

        if (buf_len == 0)
        {
            // Request has no body
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Username and password expected in request body");
            return ESP_OK;
        }
        
        buf = new char[buf_len + 1];
        int ret = httpd_req_recv(req, buf, buf_len);

        if (ret <= 0)
        {
            // Error receiving body
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                httpd_resp_send_408(req);
            }

            delete buf;
            return ESP_FAIL;
        }

        // Request body is available
        // Add \0
        buf[buf_len] = '\0';

        int parse_err = parse_json(json, buf);

        char *username;
        char *password;
        int parse_credentials_err = FW_OK;
        if (parse_err == FW_OK)
        {
            parse_credentials_err = API::parse_credentials_json(json, &username, &password);
        }

        if (parse_err != FW_OK || parse_credentials_err != FW_OK)
        {
            if (parse_err == FW_ERR_INPUT)
            {
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, error_msg);
            }
            else if (parse_credentials_err == FW_ERR_INPUT)
            {
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Please use the correct format");
            }
            else
            {
                // FW_ERR
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Internal Server Error");
            }

            delete buf;
            cJSON_Delete(json);
            return ESP_OK;
        }

        setup_auth(username, password); 

        httpd_resp_send(req, "changed", HTTPD_RESP_USE_STRLEN);
        delete buf;
        cJSON_Delete(json);
        return ESP_OK;
    }

    int API::parse_credentials_json(cJSON *json, char **username_str, char **password_str) {
        if (!cJSON_IsObject(json))
        {
            // const char msg[] = "Expected JSON object as JSON root";
            return FW_ERR_INPUT;
        }

        const cJSON *username = cJSON_GetObjectItemCaseSensitive(json, "username");

        if (username == NULL)
        {
            // const char msg[] = "Missing \"username\" key";
            // set_error_msg(strlen(msg), "%s", msg);
            // ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        const cJSON *password = cJSON_GetObjectItemCaseSensitive(json, "password");

        if (password == NULL)
        {
            // const char msg[] = "Missing \"password\" key";
            // set_error_msg(strlen(msg), "%s", msg);
            // ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (!cJSON_IsString(username))
        {
            // const char msg[] = "Expected \"username\" to be a string";
            // set_error_msg(strlen(msg), "%s", msg);
            // ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (!cJSON_IsString(password))
        {
            // const char msg[] = "Expected \"password\" to be a string";
            // set_error_msg(strlen(msg), "%s", msg);
            // ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        *username_str = cJSON_GetStringValue(username);
        *password_str = cJSON_GetStringValue(password);

        return FW_OK;
    }

    // JSON 
    char *API::construct_json_api()
    {
        api_endpoint_t *api_ptr = endpoint_head;
        cJSON *endpoints_json = cJSON_CreateArray();

        while (api_ptr != NULL)
        {
            cJSON_AddItemToArray(endpoints_json, construct_json_api_endpoint(api_ptr));

            api_ptr = api_ptr->next;
        }

        char *endpoints_json_str = cJSON_Print(endpoints_json);
        cJSON_Delete(endpoints_json);
        return endpoints_json_str;
    }

    cJSON *API::construct_json_api_endpoint(api_endpoint_t *api_ptr)
    {
        cJSON *endpoint_json = cJSON_CreateObject();

        cJSON_AddStringToObject(endpoint_json, "endpoint", api_ptr->uri);
        cJSON_AddStringToObject(endpoint_json, "description", api_ptr->description);
        cJSON_AddStringToObject(endpoint_json, "method", api_ptr->method);

        return endpoint_json;
    }

    char *API::construct_json_firewall()
    {
        ruleset_firewall_rule_t *rule_ptr = firewall->get_rule_head();
        cJSON *res = cJSON_CreateArray();

        size_t rule_nr = 1;
        while (rule_ptr != NULL && rule_nr <= firewall->get_rule_count())
        {
            cJSON *rule = construct_json_firewall_rule(rule_ptr->rule);
            cJSON_AddItemToArray(res, rule);
            
            rule_ptr = rule_ptr->next;
            rule_nr += 1;
        }

        char *res_str = cJSON_Print(res);
        cJSON_Delete(res);
        return res_str;
    }

    cJSON *API::construct_json_firewall_rule(const firewall_rule_t &rule)
    {
        cJSON *json_rule = cJSON_CreateObject();

        cJSON_AddNumberToObject(json_rule, "key", rule.key);
        cJSON_AddStringToObject(json_rule, "ip", rule.ip);
        cJSON_AddNumberToObject(json_rule, "src_port_start", rule.src_port_start);
        cJSON_AddNumberToObject(json_rule, "src_port_end", rule.src_port_end);
        cJSON_AddNumberToObject(json_rule, "dst_port_start", rule.dst_port_start);
        cJSON_AddNumberToObject(json_rule, "dst_port_end", rule.dst_port_end);
        cJSON_AddStringToObject(json_rule, "protocol", protocol_to_string(rule.protocol));
        cJSON_AddStringToObject(json_rule, "action", target_to_string(rule.target));
        cJSON_AddStringToObject(json_rule, "direction", direction_to_string(rule.direction));
        
        return json_rule;
    }
}
