#ifndef _LWIP_HOOKS_H_
#define _LWIP_HOOKS_H_

#include <lwip/netif.h>
#include <lwip/pbuf.h>

#include "config.h"

#if FIREWALL_ENABLED == 1

#ifdef __cplusplus
extern "C"
{
#endif

    int lwip_hook_ip4_input(struct pbuf *pbuf, struct netif *input_netif);
#define LWIP_HOOK_IP4_INPUT lwip_hook_ip4_input

    int lwip_hook_ip4_output(struct pbuf *pbuf, struct netif *netif);
#define LWIP_HOOK_IP4_OUTPUT lwip_hook_ip4_output


    int lwip_hook_ip6_input(struct pbuf *pbuf, struct netif *input_netif);
#define LWIP_HOOK_IP6_INPUT lwip_hook_ip6_input

    int lwip_hook_ip6_output(struct pbuf *pbuf, struct netif *netif);
#define LWIP_HOOK_IP6_OUTPUT lwip_hook_ip6_output


#ifdef __cplusplus
}
#endif

#endif /* FIREWALL_ENABLED */

#endif /* _LWIP_HOOKS_H_ */
