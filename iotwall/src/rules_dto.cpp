#include "rules_dto.hpp"

#include "sdkconfig.h"
#include "cstdarg"
#include "esp_log.h"
#include "stdio.h"

#define TAG "firewall_rules_dto"

namespace fw
{
    RulesDto::RulesDto()
    {
        rules_request.rules = nullptr;
    }

    RulesDto::~RulesDto()
    {
        delete[] rules_request.rules;
        cJSON_Delete(json);
        delete[] error_msg;
    }

    int RulesDto::from_json(cJSON *json, size_t max_rules)
    {
        if (!cJSON_IsObject(json))
        {
            const char msg[] = "Expected JSON object as JSON root";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        // Before (TODO)
        // const cJSON *before = cJSON_GetObjectItemCaseSensitive(json, "before");

        // if (cJSON_IsNumber(before))
        // {
        //     // TODO before key
        // }

        // Direction
        const cJSON *direction = cJSON_GetObjectItemCaseSensitive(json, "direction");

        if (direction == NULL)
        {
            const char msg[] = "Missing \"direction\" key";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (!cJSON_IsString(direction))
        {
            const char msg[] = "Expected \"direction\" to be a string";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        firewall_directions_t direction_res = string_to_directions(cJSON_GetStringValue(direction));

        if (direction_res == firewall_directions_t::DIRECTION_ERROR)
        {
            const char msg[] = "Invalid direction in \"direction\"";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        // IPv6
        const cJSON *ipv6 = cJSON_GetObjectItemCaseSensitive(json, "ipv6");

        if (ipv6 != NULL && !cJSON_IsBool(ipv6))
        {
            const char msg[] = "Expected \"ipv6\" to be a boolean";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        // bool ipv6_res = false;

        // if (ipv6)
        // {
        //     ipv6_res = cJSON_IsTrue(ipv6);
        // }

        // Rules
        const cJSON *rules_arr = cJSON_GetObjectItemCaseSensitive(json, "rules");

        if (rules_arr == NULL)
        {
            const char msg[] = "Missing \"rules\" key";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (!cJSON_IsArray(rules_arr))
        {
            const char msg[] = "Expected \"rules\" to be an array";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (cJSON_GetArraySize(rules_arr) == 0)
        {
            const char msg[] = "Rule list is empty";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (cJSON_GetArraySize(rules_arr) > max_rules)
        {
            const char msg[] = "Given number of rules exceeds the maximum number of configurable rules";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        int rules_count = cJSON_GetArraySize(rules_arr);
        firewall_rule_t *rules = new firewall_rule_t[rules_count];
        int rule_count = 0;

        cJSON *rule_obj = nullptr;
        cJSON_ArrayForEach(rule_obj, rules_arr)
        {
            if (!cJSON_IsObject(rule_obj))
            {
                const char msg[] = "Expected each item in \"rules\" to be an object";
                set_error_msg(strlen(msg), "%s", msg);
                ESP_LOGE(TAG, "%s", msg);

                delete[] rules;
                return FW_ERR_INPUT;
            }

            int err = parse_rule(rule_obj, &rules[rule_count]);
            rules[rule_count].direction = direction_res;
            rule_count++;

            if (err)
            {
                // Error message was set in subfunction
                delete[] rules;
                return err;
            }
        }

        delete[] rules_request.rules;
        rules_request.rules = rules;
        rules_request.rule_count = rule_count;
        rules_request.before = 0; // TODO

        return FW_OK;
    }

    const rules_request_t RulesDto::get_parsed_request()
    {
        return rules_request;
    }

    const char *RulesDto::get_last_error()
    {
        return error_msg;
    }

    void RulesDto::set_error_msg(const size_t len, const char *format, ...)
    {
        va_list args;
        va_start(args, format);

        delete[] error_msg;
        // +1 for the \0
        error_msg = new char[len + 1];
        vsnprintf(error_msg, len + 1, format, args);
        va_end(args);
    }

    int RulesDto::parse_rule(cJSON *rule_item, firewall_rule_t *rule)
    {
        if (rule == nullptr)
        {
            const char msg[] = "No rule pointer given";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR;
        }

        *rule = {};

        // IP
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(rule_item, "ip");

        if (ip != NULL && !cJSON_IsString(ip))
        {
            const char msg[] = "Expected \"ip\" to be a string";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (ip != NULL)
        {
            snprintf(rule->ip, 16, "%s", cJSON_GetStringValue(ip));
        }

        // SRC Port
        cJSON *src_port_start = cJSON_GetObjectItemCaseSensitive(rule_item, "src_port_start");
        uint16_t src_port_start_i;
        cJSON *src_port_end = cJSON_GetObjectItemCaseSensitive(rule_item, "src_port_end");
        uint16_t src_port_end_i;

        int src_start_err = parse_port(src_port_start, &src_port_start_i);

        if (src_start_err == FW_ERR_INPUT)
        {
            const char msg[] = "Expected \"src_port_start\" to be an integer between 0 and 65535";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (src_start_err != FW_OK)
        {
            return src_start_err;
        }

        int src_end_err = parse_port(src_port_end, &src_port_end_i);

        if (src_end_err == FW_ERR_INPUT)
        {
            const char msg[] = "Expected \"src_port_end\" to be an integer between 0 and 65535";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (src_end_err != FW_OK)
        {
            return src_end_err;
        }

        rule->src_port_start = src_port_start_i;
        rule->src_port_end = src_port_end_i;

        // DST Port
        cJSON *dst_port_start = cJSON_GetObjectItemCaseSensitive(rule_item, "dst_port_start");
        uint16_t dst_port_start_i;
        cJSON *dst_port_end = cJSON_GetObjectItemCaseSensitive(rule_item, "dst_port_end");
        uint16_t dst_port_end_i;

        int dst_start_err = parse_port(dst_port_start, &dst_port_start_i);

        if (dst_start_err == FW_ERR_INPUT)
        {
            const char msg[] = "Expected \"dst_port_start\" to be an integer between 0 and 65535";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (dst_start_err != FW_OK)
        {
            return dst_start_err;
        }

        int dst_end_err = parse_port(dst_port_end, &dst_port_end_i);

        if (dst_end_err == FW_ERR_INPUT)
        {
            const char msg[] = "Expected \"dst_port_end\" to be an integer between 0 and 65535";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (dst_end_err != FW_OK)
        {
            return dst_end_err;
        }

        rule->dst_port_start = dst_port_start_i;
        rule->dst_port_end = dst_port_end_i;

        // Protocol
        cJSON *proto = cJSON_GetObjectItemCaseSensitive(rule_item, "protocol");

        if (proto != NULL && !cJSON_IsString(proto))
        {
            const char msg[] = "Expected \"proto\" to be a string";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        // Default value
        rule->protocol = firewall_protocol_t::PROTOCOL_ALL;

        if (proto != NULL)
        {
            firewall_protocol_t proto_res = string_to_protocol(cJSON_GetStringValue(proto));

            if (proto_res == firewall_protocol_t::PROTOCOL_ALL)
            {
                const char msg[] = "Invalid protocol in \"proto\"";
                set_error_msg(strlen(msg), "%s", msg);
                ESP_LOGE(TAG, "%s", msg);

                return FW_ERR_INPUT;
            }

            rule->protocol = proto_res;
        }
        
        // Action
        cJSON *action = cJSON_GetObjectItemCaseSensitive(rule_item, "action");

        if (action == NULL)
        {
            const char msg[] = "Missing \"action\" key in rule";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        if (!cJSON_IsString(action))
        {
            const char msg[] = "Expected \"action\" to be a string";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        firewall_target_t action_res = string_to_target(cJSON_GetStringValue(action));

        if (action_res == firewall_target_t::TARGET_ERROR)
        {
            const char msg[] = "Invalid action in \"action\"";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR_INPUT;
        }

        rule->target = action_res;

        return FW_OK; 
    }

    int RulesDto::parse_port(cJSON *port_item, uint16_t *port)
    {
        if (port == nullptr)
        {
            const char msg[] = "No port pointer given";
            set_error_msg(strlen(msg), "%s", msg);
            ESP_LOGE(TAG, "%s", msg);

            return FW_ERR;
        }

        double port_item_d = cJSON_GetNumberValue(port_item);
        int port_item_i = (int)port_item_d;

        if (port_item != NULL && (!cJSON_IsNumber(port_item) || !is_int(port_item_d) || !is_valid_port(port_item_i)))
        {
            return FW_ERR_INPUT;
        }

        if (port_item != NULL)
        {
            *port = (uint16_t)port_item_i;
        }
        else
        {
            *port = 0;
        }

        return FW_OK;
    }
}
