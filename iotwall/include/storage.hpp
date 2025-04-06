#ifndef STORAGE_HPP
#define STORAGE_HPP

#include <esp_system.h>
#include <nvs_flash.h>
#include <nvs.h>


#include "config.hpp"
#include "utils.hpp"

namespace fw
{
    /**
     * @brief The Storage will handle Firewall rules in EEPROM
     *
     */
    class Storage
    {
    public:
        /**
         * @brief Construct a new Storage object
         *
         */
        Storage();

        /**
         * @brief Destroy the Storage object
         *
         */
        ~Storage();

    protected:
        /**
         * @brief retrieve the current number of firewall rules in the Storage
         *
         * @return uint8_t
         */
        uint8_t get_rule_count(bool isIp6 = false);

        /**
         * @brief store a new number of firewall rules in the Storage
         *
         * @param new_count
         */
        void store_rule_count(const uint8_t new_count, bool isIp6 = false);

        /**
         * @brief retrieve a Firewall rule from Storage
         *
         * @param key
         * @param rule Buffer for rule retrieved from storage
         * @return Error code (0 on success)
         */
        int retrieve_firewall_rule(const uint8_t key, firewall_rule_t *const rule);

        /**
         * @brief retrieve a IPv6 Firewall rule from Storage
         *
         * @param key
         * @return firewall_rule_t*
         */
        firewall_rule_ip6_t *retrieve_firewall_rule_ip6(const uint8_t key);

        /**
         * @brief store all Firewall rules in Storage
         *
         * @param rule_head
         */
        void store_all_firewall_rules(ruleset_firewall_rule_t *rule_head);

        /**
         * @brief store all Firewall IPv6 rules in Storage 
         *
         * @param rule_head
         */
        void store_all_firewall_rules_ip6(ruleset_firewall_rule_ip6_t *rule_head);

        /**
         * @brief store Firewall rule in Storage
         *
         * @param rule_ptr
         */
        void store_firewall_rule(firewall_rule_t rule);

        /**
         * @brief store Firewall IPv6 rule in Storage
         *
         * @param rule_ptr
         */
        void store_firewall_rule_ip6(firewall_rule_ip6_t rule);

        /**
         * @brief store credentials in Storage
         *
         * @param credential_ptr
         */
        void store_credentials(credential_t *credential_ptr);

        /**
         * @brief retrieve the credentials from Storage
         *
         * @return credential_t*
         */
        credential_t *retrieve_credentials();

        /**
         * @brief retrieve if the credentials are set
         *
         * @return uint8_t
         */
        uint8_t retrieve_credentials_set();

        /**
         * @brief store if the credentials are set
         *
         * @param set
         */
        void store_credentials_set(bool credentials_set=true);

        /**
         * @brief store bytes in Storage
         *
         * @param name
         * @param key
         * @param byteArray
         * @param length
         */
        bool store_bytes(const char* name, const char* key, unsigned char byteArray[], size_t length);

        /**
         * @brief retrieve bytes in Storage
         *
         * @param name
         * @param key
         * @param outBuffer
         * @param size
         */
        bool retrieve_bytes(const char* name, const char* key, unsigned char **outBuffer, size_t &size);

        /**
         * @brief retrive length of bytes in Storage
         *
         * @param byteArray
         * @param key
         * 
         * @return size_t
         */
        size_t storage_bytes_length(const char* name, const char* key);
    };
}

#endif
