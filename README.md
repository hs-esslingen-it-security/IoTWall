# IoTWall - A Host Firewall for Resource-Constrained IoT Devices

IoTWall is a host firewall designed to run on resource-constrained IoT devices, i.e., microcontrollers.
The implementation of IoTWall runs on ESP32 microcontrollers and is easy to integrate into existing code.
In addition, IoTWall provides a REST API to get, insert, update, and delete firewall rules.
Moreover, the API allows to change the credentials.
The API schema for the REST API can be found [here](iotwall_api_schema.yaml).


## Usage Note
Currently, our contribution to lwIP is not yet merged.
Therefore, you need to use [our fork of ESP-IDF](https://github.com/hs-esslingen-it-security/esp-idf/tree/v4.4.4-lwip-hooks) that uses our fork of lwIP with the egress hooks implemented.
Clone our ESP-IDF fork and check out the `v4.4.4-lwip-hooks` branch.
When using the ESP-IDF Visual Studio Code extension, you select the cloned fork when configuring the extension.


## Example Application
We provide an [example application](./esp32espidf) for ESP32 microcontrollers using ESP-IDF in.
The example application implements a UDP server that receives UDP packets and forwards them to a configurable IP.
Moreover, the example application contains an HTTPS web server.

Use the `config.h` to configure the firewall and other components.
Also replace the default certificates provided in the repository.
Copy the `secrets_example.h` file, name it `secrets.h` and adapt the configuration in the file.


## Integration Into Existing Code
Follow the steps below to integrate IoTWall into an existing IoT application.
The example application serves as an example for the steps.

- Add IoTWall as a dependency in the `idf_component.yml` file
- Create the file `lwip_hooks.h`. The name is arbitrary as long as it is included on compilation.
- In the `CMakeLists.txt`, add the following (adapt your path and filename):
```
idf_component_get_property(lwip lwip COMPONENT_LIB)
# Path where the lwip_hooks.h is located
target_compile_options(${lwip} PRIVATE "-I${PROJECT_DIR}/main/include")
target_compile_definitions(${lwip} PRIVATE ESP_IDF_LWIP_HOOK_FILENAME="lwip_hooks.h")
```

### Code Changes
Add the following to your code (usually `main.cpp`), if you have a C++ project:

```C++
#include "firewall.hpp"
#include "iotwall_api.hpp"

// -------------

static fw::Firewall *firewall;
static fw::API *firewall_api;

// -------------

extern "C"
{
    int lwip_hook_ip4_input(struct pbuf *pbuf, struct netif *input_netif)
    {
        // Firewall is not setup yet
        if (firewall->get_Firewall_status_input())
        {
            int res = firewall->is_packet_allowed(pbuf);
            return res;
        }
        return 0;
    }

    int lwip_hook_ip4_output(struct pbuf *pbuf, struct netif *netif)
    {
        // Firewall is not setup yet
        if (firewall->get_Firewall_status_output())
        {
            int res = firewall->is_packet_allowed_output(pbuf);
            return res;
        }
        return 0;
    }

    int lwip_hook_ip6_input(struct pbuf *pbuf, struct netif *input_netif)
    {
        // Firewall is not setup yet
        if (firewall->get_Firewall_status_input_ip6())
        {
            int res = firewall->is_packet_allowed_ip6(pbuf);
            return res;
        }
        return 0;
    }

    int lwip_hook_ip6_output(struct pbuf *pbuf, struct netif *netif)
    {
        // Firewall is not setup yet
        if (firewall->get_Firewall_status_output_ip6())
        {
            int res = firewall->is_packet_allowed_output_ip6(pbuf);
            return res;
        }
        return 0;
    }
}

// -------------

void init_firewall()
{
    firewall = new fw::Firewall();
    firewall_api = new fw::API(
        firewall,
        // All variables below must be defined first
        IP_ADDRESS,
        API_USERNAME,
        API_PASSWORD,
        FW_API_PORT,
        FW_API_CTRL_PORT,
        // Pass the SSL certificate and private key here
        servercert_start,
        servercert_end - servercert_start,
        prvtkey_pem_start,
        prvtkey_pem_end - prvtkey_pem_start
    );
}

// -------------

// Call this in the main function
initFirewall();
```
