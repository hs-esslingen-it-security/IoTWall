#ifndef _CONFIG_H_
#define _CONFIG_H_

#define FIREWALL_ENABLED 1
#define FW_API_PORT 8080
#define FW_API_CTRL_PORT 32768

/*
 * Logs info about received and sent packets and firewall decisions.
 * Should be disabled for measurements.
 */
// #define PACKET_PROCESSING_LOGS 1

/** Enable (1) or Disable (0) internal latency measurement */
#define PERFORMANCE_MEASUREMENTS_ENABLED 0

#define USE_STATIC_IP 1
#define STATIC_IP4 "192.168.80.130"
#define NETMASK "255.255.255.0"
#define GATEWAY "192.168.80.1"

#define UDP_PORT 8081

#define SAMPLE_WEBSERVER_PORT 8000
#define SAMPLE_WEBSERVER_CTRL_PORT 32770

#define EVAL_API_PORT 8082
#define EVAL_API_CTRL_PORT 32769

/** Forward incoming UDP packets to a predefined IP address (not to the sender) */
#define UDP_FORWARD 1
#define UDP_FORWARD_RECEIVER_IP "2.2.2.1" // "192.168.200.3"
#define UDP_FORWARD_RECEIVER_PORT 8081

#endif /* _CONFIG_H_ */
