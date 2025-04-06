#ifndef RULES_DTO_H
#define RULES_DTO_H

#include <cJSON.h>

#include "utils.hpp"

namespace fw
{
    struct rules_request_t {
        firewall_rule_t *rules;
        uint8_t rule_count;
        uint8_t before;
    };

    /**
     * Parses JSON containing rules. JSON looks like the following:
     * ```json
     * {
     *   "rules": [
     *     {
     *       // Optional (default: wildcard)
     *       "ip": "1.1.1.1",
     *       // Optional (default: any src port)
     *       "src_port_start": 8080,
     *       // Optional (default: any src port)
     *       "src_port_end": 8080,
     *       // Optional (default: any dst port)
     *       "dst_port_start": 8080,
     *       // Optional (default: any dst port)
     *       "dst_port_end": 8080,
     *       // Optional (default: any protocol)
     *       "protocol": "TCP",
     *       // Required
     *       "action": "ACCEPT"
     *     }
     *   ],
     *   // Required
     *   "direction": "INPUT",
     *   // Optional (default: false)
     *   "ipv6": false,
     *   // Optional. Rules will be appended if omitted
     *   "before": 1
     * }
     * ```
     */
    class RulesDto
    {
    
    public:
        RulesDto();
        ~RulesDto();

        /**
         * Parses given buffer that contains JSON.
         * On success, the resulting data can be read using `get_parsed_request()`.
         * @param buf String to parse
         * @param max_rules Maximum number of rules to parse.
         * This number should not exceed the maximum number of rules that the firewall can store.
         * Parsing will return a failure if number is exceeded.
         * @returns API Error Code (0 on success)
         */
        int from_json(cJSON *json, size_t max_rules);

        /**
         * Returns result from parsing rules from JSON (`from_json`).
         * Pointers are managed by this class.
         */
        const rules_request_t get_parsed_request();

        /** Returns reference to the last error message or nullptr if there was no error */
        const char *get_last_error();

    private:
        cJSON *json = nullptr;
        char *error_msg = nullptr;

        rules_request_t rules_request; // = {0}; TODO

        /**
         * Sets the error_msg string in this class to the given string.
         * 
         * @param len Length of the string to produce without \0
         * @param format format string (will be passed 1:1 to snprintf)
         * @param ... arguments for the format string (will be passed 1:1 to snprintf)
         */
        void set_error_msg(const size_t len, const char *format, ...);

        int parse_rule(cJSON *rule_item, firewall_rule_t *rule);

        /**
         * Parses a port from JSON.
         * Does not set an error message in case of FW_API_ERR_INPUT.
         * 
         * @param port_item JSON item. Can be NULL.
         * @param port Contains the parsed port on success. If the given JSON item is NULL, port will be 0.
         * @returns API Error Code (0 on success)
         */
        int parse_port(cJSON *port_item, uint16_t *port);
    };
}

#endif
