#ifndef UTILS_HPP
#define UTILS_HPP

#include <string.h>
#include <esp_log.h>

// Error codes

#define FW_OK 0
#define FW_ERR 1
/** Tried to access nullptr */
#define FW_ERR_NULLPTR 2
/** Invalid user input */
#define FW_ERR_INPUT 3

namespace fw
{
    static const uint8_t IPV4ADDRESS_LENGTH = 16;
    static const uint8_t IPV6ADDRESS_LENGTH = 46;
    static const uint8_t DIRECTIONS_LENGTH = 7;
    static const uint8_t CREDENTIALS_LENGTH = 32;

    /*! \enum
     */
    typedef enum firewall_targets : uint8_t
    {
        TARGET_DROP = 1,
        TARGET_ACCEPT = 2,
        TARGET_ERROR = 255,
    } firewall_target_t;

    /*! \enum
     */
    typedef enum firewall_protocols : uint8_t
    {
        PROTOCOL_ICMP = 1,
        PROTOCOL_TCP = 6,
        PROTOCOL_UDP = 17,
        PROTOCOL_ALL = 255,
    } firewall_protocol_t;

    /*! \enum
     */
    typedef enum firewall_directions : uint8_t
    {
        DIRECTION_INPUT = 0,
        DIRECTION_OUTPUT = 1,
        DIRECTION_ERROR = 255,

    } firewall_directions_t;

    /*! \enum
     */
    typedef enum ok : uint8_t
    {
        SUCCESS = 0,
        ERROR = 1,
        NO_ACTION = 2,
    } ok_t;

    /*! \enum
     */
    typedef enum auth : uint8_t
    {
        AUTHENTICATED = 0,
        DENIED = 1,
    } auth_t;

    typedef struct
    {
        uint8_t key;
        char ip[IPV4ADDRESS_LENGTH];
        uint16_t src_port_start;
        uint16_t src_port_end;
        uint16_t dst_port_start;
        uint16_t dst_port_end;
        firewall_protocol_t protocol;
        firewall_target_t target;
        firewall_directions_t direction;
    } firewall_rule_t;

    typedef struct
    {
        uint8_t key;
        char ip[IPV6ADDRESS_LENGTH];
        uint16_t src_port_start;
        uint16_t src_port_end;
        uint16_t dst_port_start;
        uint16_t dst_port_end;
        firewall_protocol_t protocol;
        firewall_target_t target;
        firewall_directions_t direction;
    } firewall_rule_ip6_t;

    typedef struct ruleset_firewall_rule_t
    {
        firewall_rule_t rule;
        struct ruleset_firewall_rule_t *next;
    } ruleset_firewall_rule_t;

    typedef struct ruleset_firewall_rule_ip6_t
    {
        firewall_rule_ip6_t rule;
        struct ruleset_firewall_rule_ip6_t *next;
    } ruleset_firewall_rule_ip6_t;

    /*! \enum
     */
    typedef enum firewall_status : uint8_t
    {
        OFF = 0,
        ON_IN = 1,
        ON_OUTPUT = 2,
        ON_INOUT = 3,
    } firewall_status_t;

    /*! \enum
     */
    typedef enum direction : uint8_t
    {
        PACKET_IN = 0,
        PACKET_OUTPUT = 1,
    } direction_t;

    /*! \struct
     */
    typedef struct my_packet
    {
        char ip[IPV4ADDRESS_LENGTH];
        firewall_protocol_t protocol;
        uint16_t src_port;
        uint16_t dst_port;
    } my_packet_t;

    /*! \struct
     */
    typedef struct my_packet_ip6
    {
        char ip[IPV6ADDRESS_LENGTH];
        firewall_protocol_t protocol;
        uint16_t src_port;
        uint16_t dst_port;
    } my_packet_ip6_t;

    /*! \struct
     */
    typedef struct credentials
    {
        char password[CREDENTIALS_LENGTH];
        char username[CREDENTIALS_LENGTH];
    } credential_t;

    /*! \struct
     */
    typedef struct api_endpoints
    {
        char uri[64];
        char method[7];
        char description[30];
        struct api_endpoints *next;
    } api_endpoint_t;

    /**
     * @brief converting protocol type to string
     *
     * @param protocol
     * @return String
     */
    char *protocol_to_string(firewall_protocol_t protocol);

    /**
     * @brief converting direction type to string
     *
     * @param direction
     * @return String
     */
    char *direction_to_string(firewall_directions_t direction);

    /**
     * @brief converting string to protocol type
     *
     * @param protocol
     * @return firewall_protocol_t
     */
    firewall_protocol_t string_to_protocol(const char *protocol);

    /**
     * @brief converting string to direction type
     *
     * @param direction
     * @return firewall_directions_t
     */
    firewall_directions_t string_to_directions(const char *direction);

    /**
     * @brief converting target type to string
     *
     * @param target
     * @return String
     */
    char *target_to_string(firewall_target_t target);

    /**
     * @brief converting string to target type
     *
     * @param target
     * @return firewall_target_t
     */
    firewall_target_t string_to_target(const char *target);

    /**
     * @brief returns if number is between or equal to lower and upper
     *
     * @param number
     * @param lower
     * @param upper
     * @return true
     * @return false
     */
    bool is_in_range_or_zero(const uint16_t number, const uint16_t lower, const uint16_t upper);

    /**
     * Returns true if given number is an integer (e.g., 1.0 is int, 1.01 is no int)
     */
    bool is_int(double number);

    /**
     * Returns true if given integer is a valid port (i.e., is within the valid port range).
     * 0 is treated as valid port.
     */
    bool is_valid_port(int number);

    void log_error_code(const char tag[], const int error_code);
}

#endif
