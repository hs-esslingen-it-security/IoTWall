#include "storage.hpp"

namespace fw
{
    const char TAG[] = "Storage";

    Storage::Storage()
    {

    }

    Storage::~Storage()
    {

    }

    uint8_t Storage::get_rule_count(bool isIp6)
    {
        size_t size = 0;
        unsigned char *retrieve_ptr = nullptr;

        if (isIp6)
            this->retrieve_bytes("fwSettings", "rule_count_ip6", &retrieve_ptr, size);
        else
            this->retrieve_bytes("fwSettings", "rule_count", &retrieve_ptr, size);

        if (size == 0 || *retrieve_ptr == 255)
        {
            free(retrieve_ptr);
            return 0;
        }
        
        const uint8_t rule_count = *(uint8_t *)retrieve_ptr;

        free(retrieve_ptr);

        return rule_count;
    }

    void Storage::store_rule_count(const uint8_t new_count, bool isIp6)
    {
        unsigned char bytes[1];
        bytes[0] = (unsigned char)new_count;

        if (isIp6)
            this->store_bytes("fwSettings", "rule_count_ip6", bytes, sizeof(bytes));
        else
            this->store_bytes("fwSettings", "rule_count", bytes, sizeof(bytes));
    }

    int Storage::retrieve_firewall_rule(const uint8_t key, firewall_rule_t *const rule)
    {
        if (rule == nullptr)
        {
            log_error_code(TAG, FW_ERR_NULLPTR);
            return FW_ERR_NULLPTR;
        }

        ESP_LOGD(TAG, "Read rule %u", key);

        char rulename[11]; // ip?Rule99\n
        sprintf(rulename, "ip4Rule%i", key);

        size_t size = 0;
        unsigned char *retrieve_ptr = nullptr;

        this->retrieve_bytes("fwSettings", rulename, &retrieve_ptr, size);

        if (retrieve_ptr != nullptr)
        {
            if(*retrieve_ptr != 255) // ESP8266 will always return a value if undefined
            {
                memcpy(rule, retrieve_ptr, sizeof(firewall_rule_t));
            }
            free(retrieve_ptr);
        }
        else
        {
            return FW_ERR;
        }

        return FW_OK;
    }

    firewall_rule_ip6_t *Storage::retrieve_firewall_rule_ip6(const uint8_t key)
    {
        char rulename[11]; // ip?Rule99\n
        sprintf(rulename, "ip6Rule%i", key);

        size_t size = 0;
        unsigned char *retrieve_ptr = nullptr;

        firewall_rule_ip6_t *rule_ptr = (firewall_rule_ip6_t *)malloc(sizeof(firewall_rule_ip6_t));
        this->retrieve_bytes("fwSettings", rulename, &retrieve_ptr, size);

        if (retrieve_ptr != nullptr)
        {
            if(*retrieve_ptr != 255) // ESP8266 will always return a value if undefined
            {
                memcpy(rule_ptr, retrieve_ptr, sizeof(firewall_rule_ip6_t));
            }
            free(retrieve_ptr);
        }

        return rule_ptr;
    }

    void Storage::store_all_firewall_rules(ruleset_firewall_rule_t *rule_head)
    {
        ruleset_firewall_rule_t *temp = rule_head;
        while (temp != NULL)
        {
            store_firewall_rule(temp->rule);
            temp = temp->next;
        }
    }

    void Storage::store_all_firewall_rules_ip6(ruleset_firewall_rule_ip6_t *rule_head)
    {
        ruleset_firewall_rule_ip6_t *temp = rule_head;
        while (temp != NULL)
        {
            store_firewall_rule_ip6(temp->rule);
            temp = temp->next;
        }
    }

    void Storage::store_firewall_rule(firewall_rule_t rule)
    {
        ESP_LOGD(TAG, "Store rule %u", rule.key);

        char rulename[11]; // ip?Rule99\n
        sprintf(rulename, "ip4Rule%i", rule.key);

        unsigned char ruleBytes[sizeof(firewall_rule_t)];
        memcpy(ruleBytes, &rule, sizeof(firewall_rule_t));
        this->store_bytes("fwSettings", rulename, ruleBytes, sizeof(ruleBytes));
    }

    void Storage::store_firewall_rule_ip6(firewall_rule_ip6_t rule)
    {
        char rulename[11]; // ip?Rule99\n
        sprintf(rulename, "ip6Rule%i", rule.key);

        unsigned char ruleBytes[sizeof(firewall_rule_ip6_t)];
        memcpy(ruleBytes, &rule, sizeof(firewall_rule_ip6_t));
        this->store_bytes("fwSettings", rulename, ruleBytes, sizeof(ruleBytes));

    }

    void Storage::store_credentials(credential_t *credential_ptr)
    {
        unsigned char credentialBytes[sizeof(credential_t)];
        memcpy(credentialBytes, credential_ptr, sizeof(credential_t));

        this->store_bytes("fwSettings", "credentials", credentialBytes, sizeof(credentialBytes));
    }


    credential_t *Storage::retrieve_credentials()
    {
        const char *TAG = "RETRIEVE CREDS";

        credential_t *credential_ptr = (credential_t *)malloc(sizeof(credential_t));

        size_t size = 0;
        unsigned char *retrieve_ptr = nullptr;

        this->retrieve_bytes("fwSettings", "credentials", &retrieve_ptr, size);
        
        if (retrieve_ptr != nullptr)
        {
            memcpy(credential_ptr, retrieve_ptr, sizeof(credential_t));

            //Serial.printf("username: %s | password: %s\n", credential_ptr->username, credential_ptr->password);

            if(retrieve_ptr != nullptr) //this is required for ESP8266 to compile
                free(retrieve_ptr);
        }
        else
            ESP_LOGE(TAG, "ptr empty");

        return credential_ptr;
    }


    void Storage::store_credentials_set(bool credentials_set)
    {
        if (credentials_set)
        {
            unsigned char credSetBytes[] = {1};
            this->store_bytes("fwSettings", "credSet", credSetBytes, sizeof(credSetBytes));
        }
        else
        {
            unsigned char credSetBytes[] = {0};
            this->store_bytes("fwSettings", "credSet", credSetBytes, sizeof(credSetBytes));
        }
    }

    uint8_t Storage::retrieve_credentials_set()
    {
        size_t size = 0;
        unsigned char *retrieve_ptr = nullptr;
        this->retrieve_bytes("fwSettings", "credSet", &retrieve_ptr, size);

        if(retrieve_ptr)
        {
            if(*retrieve_ptr != 255) // ESP8266 will always return a value if undefined
            {
                free(retrieve_ptr);
                return 1;
            }
            free(retrieve_ptr);
        }

        return 0;
    }

    bool Storage::store_bytes(const char* name, const char* key, unsigned char byteArray[], size_t length)
    {
        const char* TAG = "STORE";

        nvs_handle_t my_handle;
        nvs_open(name, NVS_READWRITE, &my_handle);
        nvs_set_blob(my_handle, key, byteArray, length);
        nvs_commit(my_handle);

        ESP_LOGI(TAG, "%s", key);

        nvs_close(my_handle);

        return false;
    }

    bool Storage::retrieve_bytes(const char* name, const char* key, unsigned char **outBuffer, size_t &size)
    {
        const char* TAG = "RETRIEVE";
        ESP_LOGD(TAG, "Flash read: %s", key);

        nvs_handle_t my_handle;
        nvs_open(name, NVS_READWRITE, &my_handle);

        size_t required_size = 0;
        nvs_get_blob(my_handle, key, NULL, &required_size);

        if (required_size > 0)
        {
            unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * required_size);
            nvs_get_blob(my_handle, key, buffer, &required_size);

            *outBuffer = buffer;
            size = required_size;
            nvs_close(my_handle);

            ESP_LOGD(TAG, "Flash read success");
            return true;
        }
        ESP_LOGE(TAG, "Flash read fail");

        nvs_close(my_handle);

        return false;
    }

    size_t Storage::storage_bytes_length(const char* name, const char* key)
    {
        size_t length = 0;
        return length;
    }
}
