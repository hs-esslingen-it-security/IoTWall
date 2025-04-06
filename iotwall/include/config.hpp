/*
 * Default config for the firewall. Can be overridden by applications.
 */

#ifndef FW_MAX_RULES
    /* Maximum firewall rules that can be configured in the firewall */
    #define FW_MAX_RULES 200
#endif

#ifndef FW_API_HTTPS
    /* Whether to enable HTTPS for the REST API */
    #define FW_API_HTTPS 1
#endif  
