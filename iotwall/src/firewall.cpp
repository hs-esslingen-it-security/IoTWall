#include "firewall.hpp"

namespace fw
{
    Firewall::Firewall()
    {
        this->rule_count = Storage::get_rule_count();
        //this->rule_count_ip6 = retrieve_rule_count(true);

        const char *TAG = "INTI_FW";

        ESP_LOGI(TAG, "Number of rules: %d", this->rule_count);
        ESP_LOGI(TAG, "Number of rules IPv6: %d", this->rule_count_ip6);


        for (uint8_t i = 1; i <= this->rule_count; i++)
        {
            firewall_rule_t rule;
            int res = retrieve_firewall_rule(i, &rule);

            if (res == FW_OK)
            {
                this->add_rule_to_firewall(rule, 0, false, false);
            }
        }

        for (uint8_t i = 1; i <= this->rule_count_ip6; i++)
        {
            // firewall_rule_ip6_t *rule_ptr = retrieve_firewall_rule_ip6(i);
            // this->add_rule_to_firewall(rule_ptr, 0, false, true);
        }
        this->check_Firewall_status();
    }

    Firewall::~Firewall()
    {
    }

    ruleset_firewall_rule_t *Firewall::get_rule_head()
    {
        return this->rule_head;
    }

    size_t Firewall::get_rule_count()
    {
        return this->rule_count;
    }

    void Firewall::add_rule_to_firewall(firewall_rule_t rule, uint8_t beforeKey, const bool save_in_eeprom, bool isIp6)
    {

        const char *TAG = "FW";
        ESP_LOGI(TAG, "Number of rules: %d", this->rule_count);
        
        // if(isIp6)
        // {
        //     firewall_rule_ip6_t *ptr = (firewall_rule_ip6_t*)rule_ptr;
        //     store_rule_count(this->rule_count_ip6, true);
            
        //     if (this->rule_head_ip6 == NULL)
        //     {
        //         ptr->next = NULL;
        //         this->rule_head_ip6 = ptr;
        //         if (save_in_eeprom)
        //         {
        //             Storage::store_firewall_rule_ip6(ptr);
        //         }
        //         return;
        //     }

        //     if (this->rule_head_ip6->key == beforeKey)
        //     {
        //         firewall_rule_ip6_t *temp = ptr;
        //         ptr->next = this->rule_head_ip6;
        //         this->rule_head_ip6 = ptr;
        //         while (temp != NULL)
        //         {
        //             temp->key++;
        //             temp = temp->next;
        //         }
        //         ptr->key = beforeKey;
        //     }
        //     else
        //     {
        //         firewall_rule_ip6_t *current_rule = this->rule_head_ip6;
        //         while (current_rule->key != beforeKey - 1 && current_rule->next != NULL)
        //             current_rule = current_rule->next;
        //         if (beforeKey != 0)
        //         {
        //             firewall_rule_ip6_t *temp = ptr;
        //             ptr->next = current_rule->next;
        //             while (temp != NULL)
        //             {
        //                 temp->key++;
        //                 temp = temp->next;
        //             }
        //             ptr->key = beforeKey;
        //         }
        //         else
        //             ptr->next = NULL;
        //         current_rule->next = ptr;
        //     }
        // }
        ruleset_firewall_rule_t *rule_entry = new ruleset_firewall_rule_t();
        rule_entry->rule = rule;
        store_rule_count(this->rule_count);

        
        if (this->rule_head == NULL)
        {
            rule_entry->next = NULL;
            this->rule_head = rule_entry;
            if (save_in_eeprom)
            {
                Storage::store_firewall_rule(rule);
            }
            return;
        }

        if (this->rule_head->rule.key == beforeKey)
        {
            // Insert before first rule
            ruleset_firewall_rule_t *temp = rule_entry;
            rule_entry->next = this->rule_head;
            this->rule_head = rule_entry;
            while (temp != NULL)
            {
                temp->rule.key++;
                if (temp->rule.key == this->rule_count)
                    temp = NULL;
                else
                    temp = temp->next;
            }
            rule_entry->rule.key = beforeKey;
        }
        else
        {
            // Insert/append somewhere after first rule
            ruleset_firewall_rule_t *current_rule = this->rule_head;
            while (current_rule->rule.key != beforeKey - 1 && current_rule->next != NULL)
            {
                current_rule = current_rule->next;
            }
            if (beforeKey != 0)
            {
                ruleset_firewall_rule_t *temp = rule_entry;
                rule_entry->next = current_rule->next;
                while (temp != NULL)
                {
                    temp->rule.key++;
                    temp = temp->next;
                }
                rule_entry->rule.key = beforeKey;
            }
            else
            {
                rule_entry->next = NULL;
            }
            current_rule->next = rule_entry;
        }

        if (save_in_eeprom)
        {
            Storage::store_all_firewall_rules(this->rule_head);
        }

        this->check_Firewall_status();

    }

    void Firewall::add_new_rule_to_firewall(firewall_rule_t rule, uint8_t beforeKey, bool isIp6)
    {
        if (isIp6)
        {
            return;
            // if (this->rule_count_ip6 >= FW_MAX_RULES)
            //     return;

            // firewall_rule_ip6_t *ptr = (firewall_rule_ip6_t*)rule_ptr;
            // ptr->key = ++this->rule_count_ip6;

            // add_rule_to_firewall((firewall_rule_ip6_t*)rule_ptr, beforeKey, true, true);
        }
        else
        {
            if (this->rule_count >= FW_MAX_RULES)
                return;

            rule.key = ++this->rule_count;

            add_rule_to_firewall(rule, beforeKey);
        }
        this->check_Firewall_status();
        return;
    }

    int Firewall::get_rule_from_firewall(const uint8_t key, firewall_rule_t *const rule)
    {
        ruleset_firewall_rule_t *rule_ptr = this->rule_head;
        if (this->rule_head == NULL)
            return FW_ERR;
    
        while (rule_ptr->rule.key != key)
        {
            if (rule_ptr->next == NULL)
                return FW_ERR;
            else
                rule_ptr = rule_ptr->next;
        }
    
        if (rule != nullptr)
        {
            *rule = rule_ptr->rule;
            return FW_OK;
        }

        return FW_ERR;
    }

    ok_t Firewall::delete_rule_from_firewall(const uint8_t key)
    {
        if (this->rule_head == NULL)
            return NO_ACTION;
    
        ruleset_firewall_rule_t *current_rule = this->rule_head;
        ruleset_firewall_rule_t *previous_rule = NULL;
        ruleset_firewall_rule_t *temp = NULL;
    
        while (current_rule->rule.key != key)
        {
            if (current_rule->next == NULL)
                return NO_ACTION;
            else
            {
                previous_rule = current_rule;
                current_rule = current_rule->next;
            }
        }
        if (current_rule == this->rule_head)
        {
            this->rule_head = rule_head->next;
            temp = this->rule_head;
        }
        else
        {
            previous_rule->next = current_rule->next;
            temp = previous_rule->next;
        }
        while (temp != NULL)
        {
            temp->rule.key--;
            temp = temp->next;
        }

        delete current_rule;
        current_rule = nullptr;
        this->rule_count--;
        Storage::store_rule_count(this->rule_count);
        if (this->rule_count != 0)
            Storage::store_all_firewall_rules(rule_head);

        this->check_Firewall_status();
        return SUCCESS;
    }

    ok_t Firewall::delete_all_rules_from_firewall()
    {
        if (this->rule_head == NULL)
            return NO_ACTION;

        ruleset_firewall_rule_t *current_rule = this->rule_head;
        ruleset_firewall_rule_t *previous_rule = NULL;

        while (current_rule != NULL)
        {
            previous_rule = current_rule;
            current_rule = previous_rule->next;
            delete previous_rule;
            previous_rule = nullptr;
        }

        this->rule_head = NULL;

        this->rule_count = 0;
        Storage::store_rule_count(this->rule_count);

        this->check_Firewall_status();
        return SUCCESS;
    }

    my_packet_t *Firewall::get_packet_information(struct pbuf *pbuf)
    {
        my_packet_t *packet = (my_packet_t *)malloc(sizeof(my_packet_t));
        const struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;
        u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);

        packet->protocol = (firewall_protocol_t)IPH_PROTO(iphdr);
        sprintf(packet->ip, "%d.%d.%d.%d", ip4_addr1_16_val(iphdr->src), ip4_addr2_16_val(iphdr->src), ip4_addr3_16_val(iphdr->src), ip4_addr4_16_val(iphdr->src));

        if (packet->protocol == PROTOCOL_ICMP)
        {
            packet->src_port = 0;
            packet->dst_port = 0;
        }
        else if (packet->protocol == PROTOCOL_TCP)
        {
            const struct tcp_hdr *tcphdr = (const struct tcp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
            packet->src_port = lwip_ntohs(tcphdr->src);
            packet->dst_port = lwip_ntohs(tcphdr->dest);
        }
        else if (packet->protocol == PROTOCOL_UDP)
        {
            const struct udp_hdr *udphdr = (const struct udp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
            packet->src_port = lwip_ntohs(udphdr->src);
            packet->dst_port = lwip_ntohs(udphdr->dest);
        }

        return packet;
    }

    my_packet_t *Firewall::get_packet_information_output(struct pbuf *pbuf)
    {
        my_packet_t *packet = (my_packet_t *)malloc(sizeof(my_packet_t));
        const struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;
        u16_t iphdr_hlen = IPH_HL_BYTES(iphdr);

        packet->protocol = (firewall_protocol_t)IPH_PROTO(iphdr);
        //packet->ip get the destination ip
        sprintf(packet->ip, "%d.%d.%d.%d", ip4_addr1_16_val(iphdr->dest), ip4_addr2_16_val(iphdr->dest), ip4_addr3_16_val(iphdr->dest), ip4_addr4_16_val(iphdr->dest));

        if (packet->protocol == PROTOCOL_ICMP)
        {
            packet->src_port = 0;
            packet->dst_port = 0;
        }
        else if (packet->protocol == PROTOCOL_TCP)
        {
            const struct tcp_hdr *tcphdr = (const struct tcp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
            packet->src_port = lwip_ntohs(tcphdr->src);
            packet->dst_port = lwip_ntohs(tcphdr->dest);
        }
        else if (packet->protocol == PROTOCOL_UDP)
        {
            const struct udp_hdr *udphdr = (const struct udp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
            packet->src_port = lwip_ntohs(udphdr->src);
            packet->dst_port = lwip_ntohs(udphdr->dest);
        }
        return packet;
    }

    bool Firewall::rule_allows_packet(const firewall_rule_t &rule, my_packet_t *packet, direction_t inputOrOutput)//
    {
        if ((rule.direction == DIRECTION_INPUT && inputOrOutput == PACKET_IN) || (rule.direction == DIRECTION_OUTPUT && inputOrOutput == PACKET_OUTPUT))
        { //INPUT rule and INPUT package
            if (strncmp(rule.ip, packet->ip, IPV4ADDRESS_LENGTH) == 0)
            {
                if (
                    (rule.protocol == PROTOCOL_ALL || rule.protocol == packet->protocol)
                    && is_in_range_or_zero(packet->src_port, rule.src_port_start, rule.src_port_end)
                    && is_in_range_or_zero(packet->dst_port, rule.dst_port_start, rule.dst_port_end)
                    && rule.target == TARGET_ACCEPT
                )
                {
                    return true;
                }
            }  
        }
        return false;
    
    }

    int Firewall::is_packet_allowed(struct pbuf *pbuf)
    {
        if (this->rule_count == 0)
            return 0;

        my_packet_t *packet = get_packet_information(pbuf);
        ruleset_firewall_rule_t *rule_ptr = this->rule_head;
        direction_t direction = PACKET_IN;
        // int input = 0; // 0 == INPUT PACKET
        while (rule_ptr != NULL)
        {
            if (rule_allows_packet(rule_ptr->rule, packet, direction))
            {
                free(packet);
                return 0;
            }
            rule_ptr = rule_ptr->next;
        }
        free(packet);
        pbuf_free(pbuf);
        return 1;
    }

    my_packet_ip6_t *Firewall::get_packet_information_ip6(struct pbuf *pbuf, bool isInput)
    {
        my_packet_ip6_t *packet = (my_packet_ip6_t *)malloc(sizeof(my_packet_ip6_t));
        // const struct ip6_hdr *iphdr = (struct ip6_hdr *)pbuf->payload;
        // u16_t iphdr_hlen = IP6H_PLEN(iphdr);

        // packet->protocol = (firewall_protocol_t)IPH_PROTO(iphdr);
        // sprintf(packet->ip, "%d.%d.%d.%d.%d.%d.%d.%d",  IP6_ADDR_BLOCK1(iphdr->src), 
        //                                                 IP6_ADDR_BLOCK2(iphdr->src), 
        //                                                 IP6_ADDR_BLOCK3(iphdr->src), 
        //                                                 IP6_ADDR_BLOCK4(iphdr->src),
        //                                                 IP6_ADDR_BLOCK5(iphdr->src), 
        //                                                 IP6_ADDR_BLOCK6(iphdr->src),
        //                                                 IP6_ADDR_BLOCK7(iphdr->src),
        //                                                 IP6_ADDR_BLOCK8(iphdr->src));

        // ip6_addr_t test;
        // ip_addr_copy_from_ip6_packed(test, iphdr->src);
        // char *ipAddr = ip6addr_ntoa((const ip6_addr_t)&test);
        // sprintf(packet->ip, ipAddr);
        // free(ipAddr);

        // if (packet->protocol == PROTOCOL_ICMP)
        //     packet->port = 0;
        // else if (packet->protocol == PROTOCOL_TCP)
        // {
        //     const struct tcp_hdr *tcphdr = (const struct tcp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
        //     packet->port = lwip_ntohs(tcphdr->dest);
        // }
        // else if (packet->protocol == PROTOCOL_UDP)
        // {
        //     const struct udp_hdr *udphdr = (const struct udp_hdr *)((const u8_t *)iphdr + iphdr_hlen);
        //     packet->port = lwip_ntohs(udphdr->dest);
        // }

        return packet;
    }

    int Firewall::is_packet_allowed_ip6(struct pbuf *pbuf, bool isInput)
    {
        // my_packet_ip6_t *packet = get_packet_information_ip6(pbuf);
        // ESP_LOGI("packet", "IPv6: %s", packet->ip);
        return 0;
    }

    int Firewall::is_packet_allowed_output(struct pbuf *pbuf)
    {   
        // no rules -> no action
        if (this->rule_count == 0)
            return 0;

        my_packet_t *packet = get_packet_information_output(pbuf);
        ruleset_firewall_rule_t *rule_ptr = this->rule_head;

        direction_t direction = PACKET_OUTPUT;
        // int output = 1; // 1 == OUTPUT PACKET
        while (rule_ptr != NULL)
        {
            if (rule_allows_packet(rule_ptr->rule, packet, direction))
                return 0;
            rule_ptr = rule_ptr->next;
        }
        free(packet);
        
        return 1;
    }

    void Firewall::check_Firewall_status()
    {
        ruleset_firewall_rule_t *rule_ptr = this->rule_head;
        int output_firewall = 0;
        int input_firewall = 0;
        while (rule_ptr != NULL && (output_firewall == 0 || input_firewall==0)){
            if(rule_ptr->rule.direction == DIRECTION_INPUT){
                input_firewall = 1;
            }
            else if (rule_ptr->rule.direction == DIRECTION_OUTPUT){
                output_firewall = 1;
            }
            rule_ptr = rule_ptr->next;
        }

        if(input_firewall == 1 && output_firewall==1){
            this->status = ON_INOUT;
        }
        else if(input_firewall == 1){
            this->status = ON_IN;
        }
        else if(output_firewall==1){
            this->status = ON_OUTPUT;
        }
        else{
            this->status = OFF;
        }

    }

    bool Firewall::get_Firewall_status_input()
    {
        if(this->status== ON_IN || this->status== ON_INOUT ){
            return true;
        }
        
        return false;
    }

    bool Firewall::get_Firewall_status_input_ip6()
    {
        if(this->status_ip6== ON_IN || this->status_ip6== ON_INOUT ){
            return true;
        }
        
        return false;
    }

    bool Firewall::get_Firewall_status_output()
    {
        if(this->status== ON_OUTPUT || this->status== ON_INOUT ){
            return true;
        }

        return false;
    }

    bool Firewall::get_Firewall_status_output_ip6()
    {
        if(this->status_ip6== ON_OUTPUT || this->status_ip6== ON_INOUT ){
            return true;
        }

        return false;
    }

    void Firewall::update_credentials_of_firewall(credential_t *credential_ptr)
    {
        Storage::store_credentials(credential_ptr);
        Storage::store_credentials_set(true);
    }

    credential_t *Firewall::get_credentials_of_firewall()
    {
        credential_t *credential_ptr = Storage::retrieve_credentials();

        return credential_ptr;
    }

    uint8_t Firewall::get_credentials_set()
    {
        uint8_t cred_set = Storage::retrieve_credentials_set();

        return cred_set;
    }
}
