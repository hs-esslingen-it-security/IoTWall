#ifndef FIREWALL_HPP
#define FIREWALL_HPP

// #include "Utils.hpp"
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/ip4.h>
#include <lwip/ip6.h>
#include <lwip/ip6_addr.h>
#include <lwip/prot/udp.h>
#include <lwip/prot/tcp.h>
#include "config.hpp"
#include "storage.hpp"


namespace fw
{
    

    /**
     * @brief The Firewall will handle Firewall rules as linked list
     *
     */
    class Firewall : public Storage
    {
    public:
        /**
         * @brief Construct a new Firewall object,
         * retrieve current number of firewall rules and
         * restore them from Storage
         */
        Firewall();

        /**
         * @brief Destroy the Firewall object
         *
         */
        ~Firewall();


        /**
         * @brief Get the current rule head, it indicates
         * the first rule position of the linked list
         *
         * @return firewall_rule_t*
         */
        ruleset_firewall_rule_t *get_rule_head();

        /**
         * @brief Get the current number of rules
         *
         * @return size_t
         */
        size_t get_rule_count();

        /**
         * @brief add a new rule to the linked list,
         * insert before provided rule-key
         * update number of rules,
         * store it in Storage if save_in_eeprom is true
         *
         * @param rule
         * @param beforeKey
         * @param save_in_eeprom
         */
        void add_rule_to_firewall(firewall_rule_t rule, uint8_t beforeKey = 0, const bool save_in_eeprom = true, bool isIp6 = false);

        /**
         * @brief add a new rule to the firewall,
         * providing request parameter
         *
         * @param rule_ptr
         * @param beforeKey
         * @return firewall_rule_t*
         */
        void add_new_rule_to_firewall(firewall_rule_t rule, uint8_t beforeKey, bool isIp6 = false);

        /**
         * @brief retrieve rule from the firewall linked list
         *
         * @param key
         * @param rule Buffer in which the rule will be returned or NULL if no rule was found
         * @return Error code (0 on success)
         */
        int get_rule_from_firewall(const uint8_t key, firewall_rule_t *const rule);

        /**
         * @brief delete rule from the firewall linked list,
         * update number of rules,
         * store new order of rules in Storage
         *
         * @param key
         * @return ok_t
         */
        ok_t delete_rule_from_firewall(const uint8_t key);

        /**
         * @brief delete all rules from the firewall linked list,
         * update number of rules,
         *
         * @return ok_t
         */
        ok_t delete_all_rules_from_firewall();

        /**
         * @brief checks if network packet is allowed to pass firewall
         * frees network buffer if rejected
         *
         * @param pbuf
         * @return int
         */
        int is_packet_allowed(struct pbuf *pbuf);

        /**
         * @brief checks if network packet is allowed to pass firewall
         * frees network buffer if rejected
         *
         * @param pbuf
         * @return int
         */
        int is_packet_allowed_ip6(struct pbuf *pbuf, bool isInput = true);
        /**
         * @brief checks if network packet is allowed to pass firewall
         * frees network buffer if rejected
         *
         * @param pbuf
         * @return int
         */
        int is_packet_allowed_output(struct pbuf *pbuf);

        /**
         * @brief checks firewall status
         */
        void check_Firewall_status();
        /**
         * @brief gets firewall status input 
         * @return bool true if firewall input is on
         */
        bool get_Firewall_status_input();

        /**
         * @brief gets firewall status input for IPv6
         * @return bool true if firewall input is on
         */
        bool get_Firewall_status_input_ip6();

        /**
         * @brief gets firewall status output 
         * @return bool true if firewall output is on
         */
        bool get_Firewall_status_output();

        /**
         * @brief gets firewall status output for IPv6
         * @return bool true if firewall output is on
         */
        bool get_Firewall_status_output_ip6();

        /**
         * @brief update credentials of firewall,
         * store it in Storage
         *
         * @param credential_t*
         */
        void update_credentials_of_firewall(credential_t *credential_ptr);

        /**
         * @brief get credentials of firewall,
         * retrive it from Storage
         *
         * @return credential_t*
         */
        credential_t *get_credentials_of_firewall();

        /**
         * @brief get if credentials of firewall are set,
         * retrive it from Storage
         *
         * @return uint8_t
         */
        uint8_t get_credentials_set();

    protected:
        /**
         * @brief checks if network packet is allowed by the rule
         *
         * @param rule_ptr
         * @param packet
         * @return true
         * @return false
         */
        bool rule_allows_packet(const firewall_rule_t &rule_ptr, my_packet_t *packet, direction_t inputOrOutput);

        /**
         * @brief prepares the necessary information to check packet
         *
         * @param pbuf
         * @return my_packet_t*
         */
        my_packet_t *get_packet_information(struct pbuf *pbuf);

        /**
         * @brief prepares the necessary information to check packet
         *
         * @param pbuf
         * @return my_packet_ip6_t*
         */
        my_packet_ip6_t *get_packet_information_ip6(struct pbuf *pbuf, bool isInput = true);

        /**
         * @brief prepares the necessary information to check packet
         *
         * @param pbuf
         * @return my_packet_t*
         */
        my_packet_t *get_packet_information_output(struct pbuf *pbuf);

        uint8_t rule_count = 0;
        uint8_t rule_count_ip6 = 0;
        ruleset_firewall_rule_t *rule_head = NULL;
        ruleset_firewall_rule_ip6_t *rule_head_ip6 = NULL;
        firewall_status_t status = OFF;
        firewall_status_t status_ip6 = OFF;
    };
}

#endif
