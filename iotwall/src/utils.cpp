#include "utils.hpp"

#include <math.h>

namespace fw
{
    char *protocol_to_string(firewall_protocol_t protocol)
    {
        char* protstr = (char *)malloc(sizeof(char) * 5);

        switch (protocol)
        {
        case PROTOCOL_ICMP:
            strlcpy(protstr, "ICMP", 5);
            return protstr;
        case PROTOCOL_TCP:
            strlcpy(protstr, "TCP", 5);
            return protstr;
        case PROTOCOL_UDP:
            strlcpy(protstr, "UDP", 5);
            return protstr;
        default:
            strlcpy(protstr, "ALL", 5);
            return protstr;
        }
    }

    
    char *direction_to_string(firewall_directions_t direction)
    {
        char* dirstr = (char *)malloc(sizeof(char) * 7);

        switch (direction)
        {
        case DIRECTION_OUTPUT:
            strlcpy(dirstr, "OUTPUT", 7);
            return dirstr;
        default:
            strlcpy(dirstr, "INPUT", 7);
            return dirstr;
        }
    }

    firewall_protocol_t string_to_protocol(const char *protocol)
    {
        if (strcmp(protocol, "ICMP") == 0)
            return PROTOCOL_ICMP;
        else if (strcmp(protocol, "TCP") == 0)
            return PROTOCOL_TCP;
        else if (strcmp(protocol, "UDP") == 0)
            return PROTOCOL_UDP;
        else
            return PROTOCOL_ALL;
    }
    
    firewall_directions_t string_to_directions(const char *direction)
    {
        if (strcmp(direction, "INPUT") == 0){
            return DIRECTION_INPUT;
        }
        else if (strcmp(direction, "OUTPUT") == 0){
            return DIRECTION_OUTPUT;
        }
        else{
            return DIRECTION_ERROR;
        }
    }

    

    char *target_to_string(firewall_target_t target)
    {
        char *target_ptr = (char *)malloc(sizeof(char) * 7);

        switch (target)
        {
        case TARGET_DROP:
            strlcpy(target_ptr, "DROP", 7);
            return target_ptr;
        case TARGET_ACCEPT:
            strlcpy(target_ptr, "ACCEPT", 7);
            return target_ptr;
        default:
            strlcpy(target_ptr, "ERROR", 7);
            return target_ptr;
        }
    }

    firewall_target_t string_to_target(const char *target)
    {
        if (strcmp(target, "DROP") == 0)
            return TARGET_DROP;
        else if (strcmp(target, "ACCEPT") == 0)
            return TARGET_ACCEPT;
        else
            return TARGET_ERROR;
    }

    bool is_in_range_or_zero(const uint16_t number, const uint16_t lower, const uint16_t upper)
    {
        if (number == 0 || (lower == 0 && upper == 0))
            return true;
    
        if (lower != 0 && upper == 0)
            return number == lower;

        if (lower == 0 && upper != 0)
            return number == upper;
        
        return number >= lower && number <= upper;
    }

    bool is_int(double number)
    {
        return ceil(number) == number;
    }

    bool is_valid_port(int number)
    {
        return number >= 0 && number <= UINT16_MAX;
    }

    void log_error_code(const char tag[], const int error_code)
    {
        ESP_LOGE(tag, "Error: %i", error_code);
    }
}
