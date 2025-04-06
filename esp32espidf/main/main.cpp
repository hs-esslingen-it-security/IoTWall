#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "stdlib.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "config.h"
#include "secrets.h"
#include "sample_webserver.hpp"
#include "eval_api.hpp"

#if PERFORMANCE_MEASUREMENTS_ENABLED == 1
#include "perf_measurements.hpp"
#endif

#if FIREWALL_ENABLED == 1
#include "firewall.hpp"
#include "iotwall_api.hpp"
#endif

#define CONFIG_EXAMPLE_IPV4 1
// #define CONFIG_EXAMPLE_IPV6 1


/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

esp_netif_t *wifi_interface;

SampleWebserver sample_webserver = SampleWebserver();
EvalApi *eval_api;

/* The event group allows multiple bits for each event,
   we use two - one for IPv4 "got ip", and
   one for IPv6 "got ip". */
const int IPV4_GOTIP_BIT = BIT0;
const int IPV6_GOTIP_BIT = BIT1;
const int WIFI_CONNECTED_BIT = BIT2;

static const char *TAG = "esp";

extern const unsigned char servercert_start[]  asm("_binary_demo_servercert_pem_start");
extern const unsigned char servercert_end[]    asm("_binary_demo_servercert_pem_end");
extern const unsigned char prvtkey_pem_start[] asm("_binary_demo_prvtkey_pem_start");
extern const unsigned char prvtkey_pem_end[]   asm("_binary_demo_prvtkey_pem_end");

#if FIREWALL_ENABLED == 1
static fw::Firewall *firewall;
static fw::API *firewall_api;

extern "C"
{
    int lwip_hook_ip4_input(struct pbuf *pbuf, struct netif *input_netif)
    {
#if PERFORMANCE_MEASUREMENTS_ENABLED
        PerfMeasurements::start_firewall_latency_measurement();
#endif

        // Firewall is not setup yet
        if (firewall->get_Firewall_status_input())
        {
            int res = firewall->is_packet_allowed(pbuf);
#ifdef PACKET_PROCESSING_LOGS
            ESP_LOGD(TAG, "Recv packet, firewall result: %d", res);
#endif

#if PERFORMANCE_MEASUREMENTS_ENABLED
        PerfMeasurements::stop_firewall_latency_measurement();
#endif
            return res;
        }
#ifdef PACKET_PROCESSING_LOGS
        ESP_LOGD(TAG, "Recv packet, firewall disabled");
#endif

#if PERFORMANCE_MEASUREMENTS_ENABLED
        PerfMeasurements::stop_firewall_latency_measurement();
#endif
        return 0;
    }

    int lwip_hook_ip4_output(struct pbuf *pbuf, struct netif *netif)
    {
        // Firewall is not setup yet
        if (firewall->get_Firewall_status_output())
        {
            int res = firewall->is_packet_allowed_output(pbuf);
#ifdef PACKET_PROCESSING_LOGS
            ESP_LOGD(TAG, "Send packet, firewall result: %d", res);
#endif
            return res;
        }
#ifdef PACKET_PROCESSING_LOGS
        ESP_LOGD(TAG, "Send packet, firewall disabled");
#endif
        return 0;
    }

    int lwip_hook_ip6_input(struct pbuf *pbuf, struct netif *input_netif)
    {
        // ESP_LOGI("ip6", "-----");
        // // Firewall is not setup yet
        // if (firewall->get_Firewall_status_input_ip6())
        // {
        //     int res = firewall->is_packet_allowed_ip6(pbuf);
        //     ESP_LOGI(TAG, "Firewall setup , return value: %d", res);
        //     return res;
        // }
        // ESP_LOGI(TAG, "Firewall not setup");

        return 0;
    }

    int lwip_hook_ip6_output(struct pbuf *pbuf, struct netif *netif)
    {
        //ESP_LOGI(LWIP_TAG, "IPv6 output hook");

        return 0;
    }
}
#endif

void event_handler(void* handler_arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT)
    {
        ESP_LOGI(TAG, "Got WiFi event: %i", event_id);

        switch (event_id)
        {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "Connecting to WiFi...");
                esp_wifi_connect();
                break;
            case WIFI_EVENT_STA_CONNECTED:
                // /* enable ipv6 */
                // tcpip_adapter_create_ip6_linklocal(TCPIP_ADAPTER_IF_STA);
                break;
            case WIFI_EVENT_STA_DISCONNECTED:
                ESP_LOGI(TAG, "Connecting to WiFi...");
                /* This is a workaround as ESP32 WiFi libs don't currently
                auto-reassociate. */
                esp_wifi_connect();
                // xEventGroupClearBits(wifi_event_group, IPV4_GOTIP_BIT);
                // xEventGroupClearBits(wifi_event_group, IPV6_GOTIP_BIT);
                break;
            default:
                break;
        }
    }
    else if (event_base == IP_EVENT)
    {
        switch (event_id)
        {
            case IP_EVENT_STA_GOT_IP:
                ESP_LOGI(TAG, "Got IP address");
                // xEventGroupSetBits(wifi_event_group, IPV4_GOTIP_BIT);
                xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
                break;
            // case SYSTEM_EVENT_AP_STA_GOT_IP6:
            //     xEventGroupSetBits(wifi_event_group, IPV6_GOTIP_BIT);
            //     break;
        }
    }
}

void initialise_wifi(void)
{
    esp_netif_init();
    wifi_interface = esp_netif_create_default_wifi_sta();

#ifdef USE_STATIC_IP
    esp_netif_dhcpc_stop(wifi_interface);
    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0 , sizeof(esp_netif_ip_info_t));
    ip_info.ip.addr = ipaddr_addr(STATIC_IP4);
    ip_info.gw.addr = ipaddr_addr(GATEWAY);
    ip_info.netmask.addr = ipaddr_addr(NETMASK);
    esp_err_t res = esp_netif_set_ip_info(wifi_interface, &ip_info);

    if (res != ESP_OK)
    {
        ESP_LOGE(TAG, "Error setting static IP");
    }
    else
    {
        ESP_LOGI(TAG, "Configured static IP address %s", STATIC_IP4);
    }
#endif

    wifi_event_group = xEventGroupCreate();
    // ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );

    esp_event_handler_instance_t instance_wifi_any_id;
    esp_event_handler_instance_t instance_ip_got_ip;

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_wifi_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_ip_got_ip));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );

    // TODO: C++20 compatibility
    // wifi_config_t wifi_config = {
    //     .sta = {
    //         .ssid = {EXAMPLE_WIFI_SSID},
    //         .password = {EXAMPLE_WIFI_PASS}
    //     }
    // };
    wifi_config_t wifi_config;
    memset(&wifi_config, 0, sizeof(wifi_config));
    sprintf (reinterpret_cast<char*>(wifi_config.sta.ssid), EXAMPLE_WIFI_SSID);
    sprintf (reinterpret_cast<char*>(wifi_config.sta.password), EXAMPLE_WIFI_PASS);


    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );

    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);

    ESP_LOGI(TAG, "Connected to WiFi");
}

#if FIREWALL_ENABLED == 1
void initFirewall()
{
    const char *ip = STATIC_IP4;
    const char *username = FW_API_USERNAME;
    const char *password = FW_API_PASSWORD;

    firewall = new fw::Firewall();
    firewall_api = new fw::API(
        firewall,
        ip,
        username,
        password,
        FW_API_PORT,
        FW_API_CTRL_PORT,
        servercert_start,
        servercert_end - servercert_start,
        prvtkey_pem_start,
        prvtkey_pem_end - prvtkey_pem_start
    );
}
#endif

// From: https://github.com/espressif/esp-idf/blob/master/examples/protocols/sockets/udp_server/main/udp_server.c
static void udp_server_task(void *pvParameters)
{
    char rx_buffer[128];
#ifdef PACKET_PROCESSING_LOGS
    char addr_str[128];
#endif
    int addr_family = (int)pvParameters;
    int ip_protocol = 0;
    struct sockaddr_in6 bind_addr;

#ifdef UDP_FORWARD
    /** Address to which response packets are sent */
    struct sockaddr_in response_dst;
    response_dst.sin_addr.s_addr = inet_addr(UDP_FORWARD_RECEIVER_IP);
    response_dst.sin_family = AF_INET;
    response_dst.sin_port = htons(UDP_FORWARD_RECEIVER_PORT);
#endif

    while (1) {

        if (addr_family == AF_INET) {
            struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *)&bind_addr;
            dest_addr_ip4->sin_addr.s_addr = htonl(INADDR_ANY);
            dest_addr_ip4->sin_family = AF_INET;
            dest_addr_ip4->sin_port = htons(UDP_PORT);
            ip_protocol = IPPROTO_IP;
        } else if (addr_family == AF_INET6) {
            bzero(&bind_addr.sin6_addr.un, sizeof(bind_addr.sin6_addr.un));
            bind_addr.sin6_family = AF_INET6;
            bind_addr.sin6_port = htons(UDP_PORT);
            ip_protocol = IPPROTO_IPV6;
        }

        int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
        if (sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Socket created");

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
        int enable = 1;
        lwip_setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable));
#endif

#if defined(CONFIG_EXAMPLE_IPV4) && defined(CONFIG_EXAMPLE_IPV6)
        if (addr_family == AF_INET6) {
            // Note that by default IPV6 binds to both protocols, it is must be disabled
            // if both protocols used at the same time (used in CI)
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        }
#endif

        int err = bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        }
        ESP_LOGI(TAG, "Socket bound, port %d", UDP_PORT);

        struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
        socklen_t socklen = sizeof(source_addr);

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
        struct iovec iov;
        struct msghdr msg;
        struct cmsghdr *cmsgtmp;
        u8_t cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

        iov.iov_base = rx_buffer;
        iov.iov_len = sizeof(rx_buffer);
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);
        msg.msg_flags = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = (struct sockaddr *)&source_addr;
        msg.msg_namelen = socklen;
#endif

        while (1) {
#ifdef PACKET_PROCESSING_LOGS
            ESP_LOGI(TAG, "Waiting for data");
#endif

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
            int len = recvmsg(sock, &msg, 0);
#else
            int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);
#endif
            // Error occurred during receiving
            if (len < 0) {
                ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
                break;
            }
            // Data received
            else {
#ifdef PACKET_PROCESSING_LOGS
                // Get the sender's ip address as string
                if (source_addr.ss_family == PF_INET) {
                    inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);

#if defined(CONFIG_LWIP_NETBUF_RECVINFO) && !defined(CONFIG_EXAMPLE_IPV6)
                    for ( cmsgtmp = CMSG_FIRSTHDR(&msg); cmsgtmp != NULL; cmsgtmp = CMSG_NXTHDR(&msg, cmsgtmp) ) {
                        if ( cmsgtmp->cmsg_level == IPPROTO_IP && cmsgtmp->cmsg_type == IP_PKTINFO ) {
                            struct in_pktinfo *pktinfo;
                            pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsgtmp);
                            ESP_LOGI(TAG, "dest ip: %s", inet_ntoa(pktinfo->ipi_addr));
                        }
                    }
#endif
                } else if (source_addr.ss_family == PF_INET6) {
                    inet6_ntoa_r(((struct sockaddr_in6 *)&source_addr)->sin6_addr, addr_str, sizeof(addr_str) - 1);
                }

                ESP_LOGI(TAG, "Received %d bytes from %s:", len, addr_str);
#endif

#ifndef UDP_FORWARD
                int err = sendto(sock, rx_buffer, len, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
#else
                int err = sendto(sock, rx_buffer, len, 0, (struct sockaddr *)&response_dst, sizeof(response_dst));
#endif
                if (err < 0) {
                    ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
                    break;
                }
            }
        }

        if (sock != -1) {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
    }
    vTaskDelete(NULL);
}

extern "C" void app_main(void)
{
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK( nvs_flash_init() );
    initialise_wifi();

    eval_api = new EvalApi(EVAL_API_PORT, EVAL_API_CTRL_PORT);

#if FIREWALL_ENABLED == 1
    ESP_LOGI(TAG, "Initializing firewall");
    initFirewall();
    ESP_LOGI(TAG, "Initialized firewall");
#endif

    sample_webserver.start(
        STATIC_IP4,
        SAMPLE_WEBSERVER_PORT,
        SAMPLE_WEBSERVER_CTRL_PORT,
        servercert_start,
        servercert_end - servercert_start,
        prvtkey_pem_start,
        prvtkey_pem_end - prvtkey_pem_start
    );

    ESP_LOGD(TAG, "CONFIG_HTTPD_MAX_REQ_HDR_LEN: %i", CONFIG_HTTPD_MAX_REQ_HDR_LEN);

#ifdef CONFIG_EXAMPLE_IPV4
        xTaskCreate(udp_server_task, "udp_server", 4096, (void*)AF_INET, 5, NULL);
#endif
#ifdef CONFIG_EXAMPLE_IPV6
        xTaskCreate(udp_server_task, "udp_server", 4096, (void*)AF_INET6, 5, NULL);
#endif
}