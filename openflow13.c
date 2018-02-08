/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ftrace.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include "openflow_spec.h"
#include "openflow.h"
#include "openflow13.h"


extern struct flow_table *flow_table;
//extern struct pbuffer *buffer;
extern struct pbuffer *pk_buffer;

// Internal functions
void packet_fields_parser(u8 *pBuffer, struct packet_fields *fields);
int flowmatch13(u8 *pBuffer, int port, u8 table_id, struct packet_fields *fields);
void packet_in13(struct sk_buff *skb, struct net_device *dev, u16 pisize, u8 port, u8 reason, int flow);
int meter_handler(u32 id, u16 bytes);
u32 get_bound_flows(u32 id);

/*
 *	Main OpenFlow 13  lookup Function
 *
 *	@param p_uc_data - pointer to the packet buffer.
 *	@param ul_size - Size of the packet.
 *	@param port	- In Port.
 *
 */
void nnOF13_tablelookup(struct sk_buff *skb, struct net_device *dev, int port, struct output_list *output_list)
{
    u8 *p_uc_data = skb->data; 
    u16 ul_size = skb->len;
    u16 packet_size = ul_size;
    u8 table_id = 0;
    u8 output_id = 0;
    struct packet_fields fields = {0};
    packet_fields_parser(p_uc_data, &fields);
    
    while(1)	// Loop through goto_tables until we get a miss
    {
        flow_table->table_counters[table_id].lookup_count++;
        // Check if packet matches an existing flow
        int i = flowmatch13(p_uc_data, port, table_id, &fields);
        if(i < 0){
            output_list->outport[output_id] = PORT_DROP;
            output_list->skb[output_id] = NULL; 
            output_list->dev[output_id] = NULL;
            kfree_skb(skb);
            return;  // Return no match
        }
        trace_printk(KERN_INFO "nn_OpenFlow13: Matched flow %d, table %d\r\n", i+1, table_id);
        flow_table->flow_counters[i].hitCount++;                // Increment flow hit count
        flow_table->flow_counters[i].bytes += packet_size;
        flow_table->flow_counters[i].lastmatch = (int)get_seconds(); // Update last flow match
        flow_table->table_counters[table_id].matched_count++;   // Increment flow match count
        flow_table->table_counters[table_id].byte_count += packet_size;
        // If there are no instructions then it's a DROP so just return
        if(flow_table->ofp13_oxm[i].inst_size == 0) return;
        // Process Instructions
        // The order is Meter -> Apply -> Clear -> Write -> Metadata -> Goto
        void *insts[8] = {0};
        int inst_size = 0;
        struct ofp13_instruction *inst_ptr;
        
        while(inst_size < flow_table->ofp13_oxm[i].inst_size)
        {
            inst_ptr = (u8*)&flow_table->ofp13_oxm[i].inst + inst_size;
            insts[ntohs(inst_ptr->type)] = inst_ptr;
            inst_size += ntohs(inst_ptr->len);
        }
        
        if(insts[OFPIT13_METER] != NULL)
        {
            struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
            int meter_ret = meter_handler(ntohl(inst_meter->meter_id), packet_size);
            if(meter_ret == METER_DROP) // Process meter id (provide byte count for counters)
            {
                // Packet must be dropped
                trace_printk(KERN_INFO "openflow_13.c: Metering dropping packet\r\n");
                output_list->outport[output_id] = PORT_DROP;
                output_list->skb[output_id] = NULL; 
                output_list->dev[output_id] = NULL;
                kfree_skb(skb);
                return;
            }
            else if(meter_ret == METER_NOACT)
            {
                trace_printk(KERN_INFO "openflow_13.c: Metering, no action taken\r\n");
            }
        }
        
        if(insts[OFPIT13_APPLY_ACTIONS] != NULL)
        {
            trace_printk(KERN_INFO "openflow_13.c: Actions, Applying actions\r\n");
            bool recalculate_ip_checksum = false;
            struct ofp13_instruction_actions *inst_actions = insts[OFPIT13_APPLY_ACTIONS];
            int act_size = 0;
            while (act_size < (ntohs(inst_actions->len) - sizeof(struct ofp13_instruction_actions)))
            {
                struct ofp13_action_header *act_hdr = (struct ofp13_action_header*)((uintptr_t)inst_actions->actions + act_size);
                switch (htons(act_hdr->type))
                {
                        // Output Action
                    case OFPAT13_OUTPUT:
                    {
                        if(recalculate_ip_checksum){
                            trace_printk(KERN_INFO "openflow_13.c: Apply actions, recalculating checksum");
                            //set_ip_checksum(p_uc_data, packet_size, fields.payload - p_uc_data);
                            recalculate_ip_checksum = false;
                        }
                        
                        struct ofp13_action_output *act_output = (struct ofp13_action_output*)act_hdr;
                        if (htonl(act_output->port) < OFPP13_MAX && htonl(act_output->port) != port)
                        {
                            trace_printk(KERN_INFO "nn_OpenFlow13: Output to port %d (%d bytes)\r\n", ntohl(act_output->port), packet_size);
                            int outport = ntohl(act_output->port);
                            if(flow_table->port_status[outport-1] == true)
                            {
                                trace_printk(KERN_INFO "nn_OpenFlow13: Output to active port %d (%d bytes)\r\n", ntohl(act_output->port), packet_size);
                                output_list->outport[output_id] = outport;
                                output_list->skb[output_id] = skb; 
                                output_list->dev[output_id] = dev;
                                skb = skb_copy(skb, GFP_ATOMIC);
                                output_id++;
                                if (output_id == MAX_OUTPUTS) return;
                            }
                        } else if (htonl(act_output->port) == OFPP13_IN_PORT)
                        {
                            //printk(KERN_INFO "nn_OpenFlow13: Output to in_port %d (%d bytes)\r\n", port, packet_size);
                            int outport = (1<< (port-1));
                            output_list->outport[output_id] = outport;
                            output_list->skb[output_id] = skb; 
                            output_list->dev[output_id] = dev;
                            skb = skb_copy(skb, GFP_ATOMIC);
                            output_id++;
                            if (output_id == MAX_OUTPUTS) return;
                        } else if (htonl(act_output->port) == OFPP13_NORMAL)
                        {
                            //printk(KERN_INFO "nn_OpenFlow13: Output to port NORMAL\n");
                            output_list->outport[output_id] = OFPP13_NORMAL;
                            output_list->skb[output_id] = skb; 
                            output_list->dev[output_id] = dev;
                            skb = skb_copy(skb, GFP_ATOMIC);
                            output_id++;
                            if (output_id == MAX_OUTPUTS) return;
                        } else if (htonl(act_output->port) == OFPP13_CONTROLLER)
                        {
                            //printk(KERN_INFO "nn_OpenFlow13: Output to controller (%d bytes)\r\n", packet_size);
                            struct sk_buff *pi_skb;
                            int pisize = ntohs(act_output->max_len);
                            if (pisize > packet_size) pisize = packet_size;
                            // Create a copy of the skb to send to the controller
                            pi_skb = skb_copy(skb, GFP_ATOMIC);
                            if (pi_skb) 
                            {
                                packet_in13(pi_skb, dev, pisize, port, OFPR13_ACTION, i);
                            }
                        } else if (htonl(act_output->port) == OFPP13_FLOOD || htonl(act_output->port) == OFPP13_ALL)
                        {
                            //if (htonl(act_output->port) == OFPP13_FLOOD) printk(KERN_INFO "nn_OpenFlow13: Output to FLOOD (%d bytes)\r\n", packet_size);
                            //if (htonl(act_output->port) == OFPP13_ALL) printk(KERN_INFO "nn_OpenFlow13: Output to ALL (%d bytes)\r\n", packet_size);
                            output_list->outport[output_id] = OFPP13_FLOOD;
                            output_list->skb[output_id] = skb; 
                            output_list->dev[output_id] = dev;
                            skb = skb_copy(skb, GFP_ATOMIC);
                            output_id++;
                            if (output_id == MAX_OUTPUTS) return;                           
                        }
                    }
                        break;

                        // Apply group
                    case OFPAT13_GROUP:
                    {
                        uint8_t act_size = sizeof(struct ofp13_bucket);
                        struct ofp13_action_group *act_group = (struct ofp13_action_group*)act_hdr;
                        struct ofp13_bucket *bucket_hdr;
                        struct ofp13_action_header *act_hdr;
                        trace_printk(KERN_INFO "nn_OpenFlow13: Group ID = %d\r\n", ntohl(act_group->group_id));
                        bucket_hdr = (struct ofp13_bucket *)flow_table->action_buckets[flow_table->group_table[ntohl(act_group->group_id)-1].bucket_id-1].data;
                        trace_printk(KERN_INFO "nn_OpenFlow13: Bucket ID = %d\r\n", flow_table->group_table[ntohl(act_group->group_id)-1].bucket_id);
                        if (htons(bucket_hdr->len == sizeof(struct ofp13_bucket))) break;   // No actions
                        while (act_size < htons(bucket_hdr->len))
                        {
                            trace_printk(KERN_INFO "nn_OpenFlow13: act_size = %d - bucket length = %d\r\n", act_size, htons(bucket_hdr->len));
                            act_hdr = (struct ofp13_action_header*)((uintptr_t)bucket_hdr + act_size);
                            trace_printk(KERN_INFO "nn_OpenFlow13: Action type = %d\r\n", htons(act_hdr->type));
                            if (htons(act_hdr->type) == OFPAT13_OUTPUT)
                            {
                                struct ofp13_action_output *act_output = act_hdr;
                                if (htonl(act_output->port) < OFPP13_MAX && htonl(act_output->port) != port)
                                {
                                    int outport = ntohl(act_output->port);
                                    trace_printk(KERN_INFO "nn_OpenFlow13: Port %d  - status %d\r\n", outport, flow_table->port_status[outport-1]);
                                    if(flow_table->port_status[outport-1] == true)
                                    {
                                        //printk(KERN_INFO "nn_OpenFlow13: Output to port %d (%d bytes)\r\n", outport, packet_size);
                                        output_list->outport[output_id] = outport;
                                        output_list->skb[output_id] = skb; 
                                        output_list->dev[output_id] = dev;
                                        skb = skb_copy(skb, GFP_ATOMIC);
                                        output_id++;
                                        if (output_id == MAX_OUTPUTS) return;
                                    }
                                } else if (htonl(act_output->port) == OFPP13_IN_PORT)
                                {
                                    printk(KERN_INFO "nn_OpenFlow13: Output = IN_PORT \r\n");
                                } else if (htonl(act_output->port) == OFPP13_FLOOD)
                                {
                                    printk(KERN_INFO "nn_OpenFlow13: Output = FLOOD \r\n");
                                } else if (htonl(act_output->port) == OFPP13_ALL)
                                {
                                    printk(KERN_INFO "nn_OpenFlow13: Output = ALL \r\n");
                                } else if (htonl(act_output->port) == OFPP13_CONTROLLER)
                                {
                                    printk(KERN_INFO "nn_OpenFlow13: Output = CONTROLLER \r\n");
                                } else if (htonl(act_output->port) == OFPP13_NORMAL)
                                {
                                    printk(KERN_INFO "nn_OpenFlow13: Output = NORMAL \r\n");
                                }
                            }
                            act_size += htons(act_hdr->len);
                        }                     
                    }
                        break; 
                        
                        // Push a VLAN tag
                    case OFPAT13_PUSH_VLAN:
                    {
                        struct ofp13_action_push *push = (struct ofp13_action_push*)act_hdr;
                        memmove(p_uc_data+16, p_uc_data+12, packet_size-12);
                        memcpy(p_uc_data+12, &push->ethertype, 2);
                        if (fields.isVlanTag){
                            memcpy(p_uc_data+14, p_uc_data+18, 2);
                        } else {
                            memset(p_uc_data+14, 0, 2);
                        }
                        packet_size += 4;
                        ul_size += 4;
                        fields.payload += 4;
                        fields.isVlanTag = true;
                    }
                        break;
                        
                        // Pop a VLAN tag
                    case OFPAT13_POP_VLAN:
                        if(fields.isVlanTag){
                            memmove(p_uc_data+12, p_uc_data+16, packet_size-16);
                            packet_size -= 4;
                            ul_size -= 4;
                            fields.payload -= 4;
                            if(fields.payload == p_uc_data+14){
                                fields.isVlanTag = false;
                            }
                        }
                        break;
                        
                        // Push an MPLS tag
                    case OFPAT13_PUSH_MPLS:
                    {
                        u8 mpls[4] = {0, 0, 1, 0}; // zeros with bottom stack bit ON
                        if (fields.eth_prot == htons(0x0800)){
                            struct iphdr *hdr = (struct iphdr*)fields.payload;
                            mpls[3] = hdr->ttl;
                        } else if (fields.eth_prot == htons(0x8847) || fields.eth_prot == htons(0x8848)){
                            memcpy(mpls, fields.payload, 4);
                            mpls[2] &= 0xFE; // clear bottom stack bit
                        }
                        struct ofp13_action_push *push = (struct ofp13_action_push*)act_hdr;
                        u16 payload_offset = fields.payload - p_uc_data;
                        memmove(fields.payload + 4, fields.payload, packet_size - payload_offset);
                        memcpy(fields.payload - 2, &push->ethertype, 2);
                        memcpy(fields.payload, mpls, 4);
                        packet_size += 4;
                        ul_size += 4;
                        fields.eth_prot = push->ethertype;
                    }
                        break;
                        
                        // Pop an MPLS tag
                    case OFPAT13_POP_MPLS:
                        if(fields.eth_prot == htons(0x8847) || fields.eth_prot == htons(0x8848)){
                            struct ofp13_action_pop_mpls *pop = (struct ofp13_action_pop_mpls*)act_hdr;
                            u16 payload_offset = fields.payload - p_uc_data;
                            memmove(fields.payload, fields.payload + 4, packet_size - payload_offset - 4);
                            memcpy(fields.payload - 2, &pop->ethertype, 2);
                            packet_size -= 4;
                            ul_size -= 4;
                            packet_fields_parser(p_uc_data, &fields);
                        }
                        break;
                        
                        // Set Field Action
                    case OFPAT13_SET_FIELD:
                    {
                        //printk(KERN_INFO "nn_OpenFlow13: Set Field action.\n");
                        struct ofp13_action_set_field *act_set_field = (struct ofp13_action_set_field*)act_hdr;
                        struct oxm_header13 oxm_header;
                        u8 oxm_value[8];
                        memcpy(&oxm_header, act_set_field->field,4);
                        oxm_header.oxm_field = oxm_header.oxm_field >> 1;
                        switch(oxm_header.oxm_field)
                        {
                                // Set VLAN ID
                            case OFPXMT_OFB_VLAN_VID:
                                // SPEC: The use of a set-field action assumes that the corresponding header field exists in the packet
                                if(fields.isVlanTag){
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
                                    p_uc_data[14] = (p_uc_data[14] & 0xf0) | (oxm_value[0] & 0x0f);
                                    p_uc_data[15] = oxm_value[1];
                                    memcpy(&fields.vlanid, oxm_value, 2);
                                    //printk(KERN_INFO "nn_OpenFlow13: Set VID %u", (ntohs(fields.vlanid) - OFPVID_PRESENT));
                                }
                                break;
                                
                            case OFPXMT_OFB_VLAN_PCP:
                                if(fields.isVlanTag){
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
                                    p_uc_data[14] = (oxm_value[0]<<5) | (p_uc_data[14] & 0x0f);
                                    //printk(KERN_INFO "nn_OpenFlow13: Set VLAN_PCP %u", oxm_value[0]);
                                }
                                break;
                                
                                // Set Source Ethernet Address
                            case OFPXMT_OFB_ETH_SRC:
                                memcpy(p_uc_data + 6, act_set_field->field + sizeof(struct oxm_header13), 6);
                                break;
                                // Set Destination Ethernet Address
                            case OFPXMT_OFB_ETH_DST:
                                memcpy(p_uc_data, act_set_field->field + sizeof(struct oxm_header13), 6);
                                break;
                                
                                // Set Ether Type
                            case OFPXMT_OFB_ETH_TYPE:
                                memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
                                memcpy(fields.payload-2, oxm_value, 2);
                                memcpy(&fields.eth_prot, oxm_value, 2);
                                break;
                                
                            case OFPXMT_OFB_IP_DSCP:
                                if (fields.eth_prot == htons(0x0800))
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
                                    struct iphdr *hdr = (struct iphdr*)fields.payload;
                                    hdr->tos = (oxm_value[0]<<2)|(hdr->tos&0x3);
                                    recalculate_ip_checksum = true;
                                    //printk(KERN_INFO "nn_OpenFlow13: Set IP_DSCP %u", oxm_value[0]);
                                }// TODO: IPv6
                                break;
                                
                            case OFPXMT_OFB_IP_ECN:
                                if (fields.eth_prot == htons(0x0800))
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 1);
                                    struct iphdr *hdr = (struct iphdr*)fields.payload;
                                    hdr->tos = (oxm_value[0]&0x3)|(hdr->tos&0xFC);
                                    recalculate_ip_checksum = true;
                                    //printk(KERN_INFO "nn_OpenFlow13: Set IP_ECN %u", oxm_value[0]);
                                }// TODO: IPv6
                                break;
                                
                                // Set IP protocol
                            case OFPXMT_OFB_IP_PROTO:
                                if (fields.eth_prot == htons(0x0800))	// IPv4 packet
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
                                    memcpy(fields.payload + 9, oxm_value, 2);
                                    memcpy(&fields.ip_prot, oxm_value, 2);
                                    recalculate_ip_checksum = true;
                                }
                                // TODO: or IPv6
                                break;
                                
                                // Set Source IP Address
                            case OFPXMT_OFB_IPV4_SRC:
                                if (fields.eth_prot == htons(0x0800))	// Only set the field if it is an IPv4 packet
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 4);
                                    memcpy(fields.payload + 12, oxm_value, 4);
                                    memcpy(&fields.ip_src, oxm_value, 4);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set Destination IP Address
                            case OFPXMT_OFB_IPV4_DST:
                                if (fields.eth_prot == htons(0x0800))	// Only set the field if it is an IPv4 packet
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 4);
                                    memcpy(fields.payload + 16, act_set_field->field + sizeof(struct oxm_header13), 4);
                                    memcpy(&fields.ip_dst, act_set_field->field + sizeof(struct oxm_header13), 4);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set Source TCP port
                            case OFPXMT_OFB_TCP_SRC:
                                if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IPPROTO_TCP)	// Only set the field if it is an IPv4 TCP packet
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
                                    memcpy(fields.payload + 20, oxm_value, 2);
                                    memcpy(&fields.tp_src, oxm_value, 2);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set Destination TCP port
                            case OFPXMT_OFB_TCP_DST:
                                if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IPPROTO_TCP)	// Only set the field if it is an IPv4 TCP packet
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
                                    memcpy(fields.payload + 22, oxm_value, 2);
                                    memcpy(&fields.tp_dst, oxm_value, 2);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set Source UDP port
                            case OFPXMT_OFB_UDP_SRC:
                                if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IPPROTO_UDP)	// Only set the field if it is an IPv4 UDP packet
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
                                    memcpy(fields.payload + 20, oxm_value, 2);
                                    memcpy(&fields.tp_src, oxm_value, 2);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set Destination UDP port
                            case OFPXMT_OFB_UDP_DST:
                                if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IPPROTO_UDP)	// Only set the field if it is an IPv4 UDP packet
                                {
                                    memcpy(oxm_value, act_set_field->field + sizeof(struct oxm_header13), 2);
                                    memcpy(fields.payload + 22, oxm_value, 2);
                                    memcpy(&fields.tp_dst, oxm_value, 2);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set ICMP type
                            case OFPXMT_OFB_ICMPV4_TYPE:
                                if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IPPROTO_ICMP)	// Only set the field if it is an ICMP packet
                                {
                                    struct iphdr *iphdr = (struct iphdr*)fields.payload;
                                    u8 *icmp = fields.payload + (iphdr->tot_len * 4);
                                    memcpy(icmp, act_set_field->field + sizeof(struct oxm_header13), 1);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set ICMP code
                            case OFPXMT_OFB_ICMPV4_CODE:
                                if (fields.eth_prot == htons(0x0800) && fields.ip_prot == IPPROTO_ICMP)	// Only set the field if it is an ICMP packet
                                {
                                    struct iphdr *iphdr = (struct iphdr*)fields.payload;
                                    u8 *icmp = fields.payload + (iphdr->tot_len * 4);
                                    memcpy(icmp+1, act_set_field->field + sizeof(struct oxm_header13), 1);
                                    recalculate_ip_checksum = true;
                                }
                                break;
                                
                                // Set ARP opcode
                            case OFPXMT_OFB_ARP_OP:
                                if (fields.eth_prot == htons(0x0806))	// Only set the field if it is a ARP packet
                                {
                                    memcpy(fields.payload + 6, act_set_field->field + sizeof(struct oxm_header13), 2);
                                }
                                break;
                                
                                // Set ARP source IP address
                            case OFPXMT_OFB_ARP_SPA:
                                if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
                                {
                                    memcpy(fields.payload + 14, act_set_field->field + sizeof(struct oxm_header13), 4);
                                }
                                break;
                                
                                // Set ARP target IP address
                            case OFPXMT_OFB_ARP_TPA:
                                if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
                                {
                                    memcpy(fields.payload + 24, act_set_field->field + sizeof(struct oxm_header13), 4);
                                }
                                break;
                                
                                // Set ARP source hardware address
                            case OFPXMT_OFB_ARP_SHA:
                                if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
                                {
                                    memcpy(fields.payload + 8, act_set_field->field + sizeof(struct oxm_header13), 6);
                                }
                                break;
                                
                                // Set ARP target hardware address
                            case OFPXMT_OFB_ARP_THA:
                                if (fields.eth_prot == htons(0x0806))	// Only set the field if it is an ARP packet
                                {
                                    memcpy(fields.payload + 18, act_set_field->field + sizeof(struct oxm_header13), 6);
                                }
                                break;
                        }
                    }
                }
                act_size += htons(act_hdr->len);
            }
            
            if (recalculate_ip_checksum) {
                trace_printk(KERN_INFO "openflow_13.c: Apply actions, recalculating checksum");
                //*** set_ip_checksum(p_uc_data, packet_size, fields.payload + 14);
            }
        }
        
        if(insts[OFPIT13_GOTO_TABLE] != NULL)
        {
            struct ofp13_instruction_goto_table *inst_goto_ptr = insts[OFPIT13_GOTO_TABLE];
            if (table_id >= inst_goto_ptr->table_id) {
                //printk(KERN_INFO "nn_OpenFlow13: Goto loop detected, aborting (cannot goto to earlier/same table)");
                output_list->outport[output_id] = PORT_DROP;
                output_list->skb[output_id] = NULL; 
                output_list->dev[output_id] = NULL;
                kfree_skb(skb);
                return;  // Return no match
            }
            table_id = inst_goto_ptr->table_id;
            //printk(KERN_INFO "nn_OpenFlow13: Goto table %d", table_id);
        } else
        {
            output_list->outport[output_id] = PORT_DROP;
            output_list->skb[output_id] = NULL; 
            output_list->dev[output_id] = NULL;
            kfree_skb(skb);
            return;  // Return no match
        }
    }
    printk("openflow_13.c: Returning DROP");
    output_list->outport[output_id] = PORT_DROP;
    output_list->skb[output_id] = NULL; 
    output_list->dev[output_id] = NULL;
    kfree_skb(skb);
    return;  // Return no match
}


/*
 *	Populate the packet header fields.
 *
 *	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
 *	@param *fields - pointer the struct to store the field values.
 *
 */
void packet_fields_parser(u8 *pBuffer, struct packet_fields *fields)
{
    static const u8 vlan1[2] = { 0x81, 0x00 };
    static const u8 vlan2[2] = { 0x88, 0xa8 };
    static const u8 vlan3[2] = { 0x91, 0x00 };
    static const u8 vlan4[2] = { 0x92, 0x00 };
    static const u8 vlan5[2] = { 0x93, 0x00 };
    
    fields->isVlanTag = false;
    u8 *eth_type = pBuffer + 12;
    while(memcmp(eth_type, vlan1, 2)==0
          || memcmp(eth_type, vlan2, 2)==0
          || memcmp(eth_type, vlan3, 2)==0
          || memcmp(eth_type, vlan4, 2)==0
          || memcmp(eth_type, vlan5, 2)==0){
        if(fields->isVlanTag == false){ // save outermost value
            u8 tci[2] = { eth_type[2]&0x0f, eth_type[3] };
            memcpy(&fields->vlanid, tci, 2);
        }
        fields->isVlanTag = true;
        eth_type += 4;
    }
    memcpy(&fields->eth_prot, eth_type, 2);
    fields->payload = eth_type + 2; // payload points to ip_hdr, etc.

    if(ntohs(fields->eth_prot) == 0x0806){
        memcpy(&fields->arp_op, fields->payload + 6, 2);    // ARP OP Code
        memcpy(&fields->arp_sha, fields->payload + 8, 6);    // ARP Sender Hardware Address
        memcpy(&fields->arp_spa, fields->payload + 14, 4);    // ARP Sender IP Address
        memcpy(&fields->arp_tha, fields->payload + 18, 6);    // ARP Target Hardware Address
        memcpy(&fields->arp_tpa, fields->payload + 24, 4);    // ARP Target IP Address
    }
    
    if(ntohs(fields->eth_prot) == 0x0800){
        struct iphdr *iphdr = (struct iphdr *)fields->payload;
        u8 *ip_payload = (u8*)fields->payload + (iphdr->ihl * 4);
        fields->ip_src = iphdr->saddr;
        fields->ip_dst = iphdr->daddr;
        fields->ip_prot = iphdr->protocol;
        if(iphdr->protocol==IPPROTO_TCP){
            struct tcphdr *tcphdr = (struct tcphdr*)ip_payload;
            fields->tp_src = tcphdr->source;
            fields->tp_dst = tcphdr->dest;
        }
        if(iphdr->protocol==IPPROTO_UDP){
            struct udphdr *udphdr = (struct udphdr*)ip_payload;
            fields->tp_src = udphdr->source;
            fields->tp_dst = udphdr->dest;
        }
    }
    fields->parsed = true;
}

/*
 *	Matches packet headers against the installed flows for OpenFlow v1.3 (0x04).
 *	Returns the flow number if it matches.
 *
 *	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
 *	@param port - The port that the packet was received on.
 *
 */
int flowmatch13(u8 *pBuffer, int port, u8 table_id, struct packet_fields *fields)
{
    int matched_flow = -1;
    int priority_match = -1;
    u8 *eth_dst = pBuffer;
    u8 *eth_src = pBuffer + 6;
    u16 oxm_value16;
    u8 oxm_ipv4[4];
    u8 oxm_apr_spa[4];
    u8 oxm_apr_tpa[4];
    int j, i;
    
    if (!fields->parsed) {
        packet_fields_parser(pBuffer, fields);
    }
    
    trace_printk("nn_OpenFlow13: Looking for match in table %d from port %d : "
          "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X eth type %4.4X (%d-%d:%d)\r\n",
          table_id, port,
          eth_src[0], eth_src[1], eth_src[2], eth_src[3], eth_src[4], eth_src[5],
          eth_dst[0], eth_dst[1], eth_dst[2], eth_dst[3], eth_dst[4], eth_dst[5],
          ntohs(fields->eth_prot),ntohs(fields->ip_prot),ntohs(fields->tp_src),ntohs(fields->tp_dst));
    
    trace_printk("nn_OpenFlow13: %d flows in table\r\n", flow_table->iLastFlow);

    
    for (i=0;i<flow_table->iLastFlow;i++)
    {
        // Make sure its an active flow
        if (flow_table->flow_counters[i].active == false) continue;
        
        // If the flow is not in the requested table then fail
        if (table_id != flow_table->flow_match13[i].table_id) continue;
        
        // If the flow has no match fields (full wild) it is an automatic match
        if (flow_table->ofp13_oxm[i].match_size ==  0)
        {
            if (matched_flow == -1 || (ntohs(flow_table->flow_match13[i].priority) > ntohs(flow_table->flow_match13[matched_flow].priority))) matched_flow = i;
            continue;
        }
        // If this flow is of a lower priority then one that is already match then there is no point going through a check.
        if (matched_flow > -1 && (ntohs(flow_table->flow_match13[matched_flow].priority) >= ntohs(flow_table->flow_match13[i].priority))) continue;
        
        // Main flow match loop
        priority_match = 0;
        u8 *hdr = flow_table->ofp13_oxm[i].match;
        u8 *tail = hdr + ntohs(flow_table->flow_match13[i].match.length) - 4;
        while (hdr < tail)
        {
            u32 field = ntohl(*(u32*)(hdr));
            u8 *oxm_value = hdr + 4;
            hdr += 4 + OXM_LENGTH(field);
            
            switch(field)
            {
                case OXM_OF_IN_PORT:
                    if (port != ntohl(*(u32*)oxm_value))
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_ETH_DST:
                    if (memcmp(eth_dst, oxm_value, 6) != 0)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_ETH_DST_W:
                    for (j=0; j<6; j++ )
                    {
                        if (oxm_value[j] != (eth_dst[j] & oxm_value[6+j])){
                            priority_match = -1;
                        }
                    }
                    break;
                    
                case OXM_OF_ETH_SRC:
                    if (memcmp(eth_src, oxm_value, 6) != 0)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_ETH_SRC_W:
                    for (j=0; j<6; j++ )
                    {
                        if (oxm_value[j] != (eth_src[j] & oxm_value[6+j])){
                            priority_match = -1;
                        }
                    }
                    break;
                    
                case OXM_OF_ETH_TYPE:
                    if (fields->eth_prot != *(u16*)oxm_value)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_IP_DSCP:
                    priority_match = -1;
                    if (fields->eth_prot == htons(0x0800)){
                        struct iphdr *iph = (struct iphdr*)fields->payload;
                        if(iph->tos >> 2 == oxm_value[0]){
                            priority_match = 0;
                        }
                    }
                    break;
                    
                case OXM_OF_IP_ECN:
                    priority_match = -1;
                    if (fields->eth_prot == htons(0x0800)){
                        struct iphdr *iph = (struct iphdr*)fields->payload;
                        if((iph->tos & 03) == oxm_value[0]){
                            priority_match = 0;
                        }
                    }
                    break;
                    
                case OXM_OF_IP_PROTO:
                    if (fields->ip_prot != *oxm_value)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_IPV4_SRC:
                    if (memcmp(&fields->ip_src, oxm_value, 4) != 0)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_IPV4_SRC_W:
                    memcpy(oxm_ipv4, &fields->ip_src, 4);
                    for (j=0; j<4; j++)
                    {
                        oxm_ipv4[j] &= oxm_value[4+j];
                    }
                    if (memcmp(oxm_ipv4, oxm_value, 4) != 0)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_IPV4_DST:
                    if (memcmp(&fields->ip_dst, oxm_value, 4) != 0)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_IPV4_DST_W:
                    memcpy(oxm_ipv4, &fields->ip_dst, 4);
                    for (j=0; j<4; j++ )
                    {
                        oxm_ipv4[j] &= oxm_value[4+j];
                    }
                    if (memcmp(oxm_ipv4, oxm_value, 4) != 0)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_TCP_SRC:
                    if (!(fields->ip_prot == 6 && fields->tp_src == *(u16*)oxm_value))
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_TCP_DST:
                    if (!(fields->ip_prot == 6 && fields->tp_dst == *(u16*)oxm_value))
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_UDP_SRC:
                    trace_printk("nn_OpenFlow13: src oxm_value - %d\r\n", *(u16*)oxm_value);
                    if (!(fields->ip_prot == 17 && fields->tp_src == *(u16*)oxm_value))
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_UDP_DST:
                    trace_printk("nn_OpenFlow13: dst oxm_value - %d\r\n", *(u16*)oxm_value);
                    if (!(fields->ip_prot == 17 && fields->tp_dst == *(u16*)oxm_value))
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_VLAN_VID:
                    if (fields->isVlanTag)
                    {
                        oxm_value16 = htons(OFPVID_PRESENT | ntohs(fields->vlanid));
                    }else{
                        oxm_value16 = htons(OFPVID_NONE);
                    }
                    if (oxm_value16 != *(u16*)oxm_value)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_VLAN_VID_W:
                    if (fields->isVlanTag)
                    {
                        oxm_value16 = htons(OFPVID_PRESENT | ntohs(fields->vlanid));
                    }else{
                        oxm_value16 = htons(OFPVID_NONE);
                    }
                    oxm_value16 &= *(u16*)(oxm_value+2);
                    if (oxm_value16 != *(u16*)oxm_value)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_VLAN_PCP:
                    if (!(fields->isVlanTag && (pBuffer[14]>>5) == oxm_value[0]))
                    {
                        priority_match = -1;
                    }
                    break;

                case OXM_OF_ARP_OP:
                    if (fields->eth_prot == htons(0x0806) && fields->arp_op == *(u16*)oxm_value)
                    {
                        priority_match = -1;
                    }
                    break;

                case OXM_OF_ARP_SPA:
                    if (fields->eth_prot == htons(0x0806) && memcmp(&fields->arp_spa, oxm_value, 4) != 0)
                    {
                        priority_match = -1;
                    }
                    break;

                case OXM_OF_ARP_TPA:
                    if (fields->eth_prot == htons(0x0806) && memcmp(&fields->arp_tpa, oxm_value, 4) != 0)
                    {
                        priority_match = -1;
                    }
                    break;

                case OXM_OF_ARP_SHA:
                    if (fields->eth_prot == htons(0x0806) && memcmp(&fields->arp_sha, oxm_value, 6) != 0)
                    {
                        priority_match = -1;
                    }
                    break;
                    
                case OXM_OF_ARP_THA:
                    if (fields->eth_prot == htons(0x0806) && memcmp(&fields->arp_tha, oxm_value, 6) != 0)
                    {
                        priority_match = -1;
                    }
                    break;                                           
            }
            
            if (priority_match == -1)
            {
                break;
            }
        }
        if (priority_match != -1)
        {
            matched_flow = i;
        }
    }
    return matched_flow;
}

void packet_in13(struct sk_buff *skb, struct net_device *dev, u16 pisize, u8 port, u8 reason, int flow)
{
    trace_printk(KERN_INFO "nn_OpenFlow13: Packet_IN request from port %d reason = %d on flow %d (%d bytes)\n", port, reason, flow+1, pisize);
    int buffer_no = -1;
    int x;
    u8 *dst_ehdr, *src_ehdr;

    for(x=0;x<(PACKET_BUFFER);x++)
    {
        trace_printk(KERN_INFO "nn_OpenFlow13: Buffer %d is set as %d\n", x, pk_buffer->buffer[x].type);
        if(pk_buffer->buffer[x].type == PB_EMPTY) 
        {
            buffer_no = x;
            break;
        }
    }
    if (buffer_no == -1 ) 
    {
        trace_printk(KERN_INFO "nn_OpenFlow13: All buffer are full!\n");
        kfree_skb(skb);
        return;   // All buffers are full
    }
    pk_buffer->buffer[buffer_no].skb = skb;
    pk_buffer->buffer[buffer_no].dev = dev;
    pk_buffer->buffer[buffer_no].age = 0;
    pk_buffer->buffer[buffer_no].size = pisize;
    pk_buffer->buffer[buffer_no].inport = port;
    pk_buffer->buffer[buffer_no].reason = reason;
    pk_buffer->buffer[buffer_no].flow = flow;
    memcpy(&pk_buffer->buffer[buffer_no].buffer, skb->data, PACKET_BUFFER_SIZE);
    pk_buffer->buffer[buffer_no].type = PB_PACKETIN;  // set type last
    // Testing only
    dst_ehdr = (u8*)&pk_buffer->buffer[buffer_no].buffer;
    src_ehdr = dst_ehdr + 6;
    trace_printk(KERN_INFO "nn_OpenFlow13: Reading Packet IN from port %d loaded into buffer %d - Src/Dst: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x / %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n", port, buffer_no, src_ehdr[0], src_ehdr[1], src_ehdr[2], src_ehdr[3], src_ehdr[4], src_ehdr[5], dst_ehdr[0], dst_ehdr[1], dst_ehdr[2], dst_ehdr[3], dst_ehdr[4], dst_ehdr[5]);         
    return;
}


/*
*   Meter processing for OF 1.3
*
*   @param  id      - meter ID to process
*   @param  bytes   - packet size (for throughput calculations)
*
*   @ret    METER_NOACT - no action needs to be taken
*   @ret    METER_DROP  - packet needs to be dropped
*   @ret    val         - increase encoded drop precedence by val (DSCP remark)
*
*/
int meter_handler(u32 id, u16 bytes)
{   
    struct timespec ts_time;
    time_t ct;    
    trace_printk(KERN_INFO "openflow_13.c: meter id %d needs processing", id);
    
    // Get associated meter entry
    int meter_index = 0;
    while(flow_table->meter_table.meter_entry[meter_index].active == true && meter_index < MAX_METER_13)
    {
        if(flow_table->meter_table.meter_entry[meter_index].meter_id == id)
        {
            trace_printk(KERN_INFO "openflow_13.c: meter entry found - continuing");
            break;
        }
            
        meter_index++;
    }
    if(flow_table->meter_table.meter_entry[meter_index].active == false || meter_index == MAX_METER_13)
    {
        trace_printk(KERN_INFO "openflow_13.c: meter entry not found - packet not dropped\n");
        return METER_NOACT;
    }
    // meter_index now holds the meter bound to the current flow
    
    // Update meter counters
    flow_table->meter_table.meter_entry[meter_index].byte_in_count += bytes;
    (flow_table->meter_table.meter_entry[meter_index].packet_in_count)++;
 
    getnstimeofday(&ts_time);
    ct = (ts_time.tv_sec * 1000) + (ts_time.tv_nsec / 1000000);

    // Check if meter has been used before
    if(flow_table->meter_table.meter_entry[meter_index].last_packet_in == 0)
    {
        // Update timer
        flow_table->meter_table.meter_entry[meter_index].last_packet_in = ct;
        
        trace_printk(KERN_INFO "openflow_13.c: first hit of meter - packet not dropped\n");
        return METER_NOACT;
    }

    // Find time delta
    int time_delta = ct - flow_table->meter_table.meter_entry[meter_index].last_packet_in;
    trace_printk(KERN_INFO "openflow_13.c: current_time = %lu - time delta = %u\n", ct, time_delta);
    
    // Update timer
    flow_table->meter_table.meter_entry[meter_index].last_packet_in = ct;

    // Check configuration flags
    int calculated_rate = 0;
    if(((flow_table->meter_table.meter_entry[meter_index].flags) & OFPMF13_KBPS) == OFPMF13_KBPS)
    {
        calculated_rate = (((bytes*8)/time_delta) * METER_CAL_KBPS);   // bit/ms == kbit/s
        trace_printk(KERN_INFO "openflow_13.c: calculated rate - %d kbps (%d bytes/ %d ms)\n", calculated_rate, bytes*8, time_delta);
    }
    else if(((flow_table->meter_table.meter_entry[meter_index].flags) & OFPMF13_PKTPS) == OFPMF13_PKTPS)
    {
        calculated_rate = ((1000/time_delta) * METER_CAL_PPS);
        trace_printk(KERN_INFO "openflow_13.c: calculated rate - %d pktps (%d ms)\n", calculated_rate, time_delta);
    }
    else
    {
        trace_printk(KERN_INFO "openflow_13.c: unsupported meter configuration - packet not dropped\n");
        return METER_NOACT;
    }

    // Check each band
    int    bands_processed = 0;
    int    highest_rate = 0;           // Highest triggered band rate
    struct ofp13_meter_band_drop * ptr_highest_band = NULL; // Store pointer to highest triggered band
    struct ofp13_meter_band_drop * ptr_band;
    ptr_band = (struct ofp13_meter_band_drop*) &(flow_table->meter_table.meter_entry[meter_index].bands);
    while(bands_processed < flow_table->meter_table.meter_entry[meter_index].band_count)
    {
        if(calculated_rate >= ptr_band->rate)
        {
            if(ptr_band->rate > highest_rate)
            {
                highest_rate = ptr_band->rate;  // Update highest triggered band rate
                ptr_highest_band = ptr_band;    // Update highest triggered band
            }           
        }
        
        ptr_band++; // Move to next band
        bands_processed++;
    }
    
    // Check if any bands triggered
    if(highest_rate == 0 || ptr_highest_band == NULL)
    {
        trace_printk(KERN_INFO "openflow_13.c: no bands triggered - packet not dropped\n");
        return METER_NOACT;
    }
    
    // Check band type
    if(ptr_highest_band->type != OFPMBT13_DROP && ptr_highest_band->type != OFPMBT13_DSCP_REMARK)
    {
        trace_printk(KERN_INFO "openflow_13.c: unsupported band type - not dropping packet\n");
        return METER_NOACT;
    }
    
    trace_printk(KERN_INFO "openflow_13.c: highest triggered band rate:%d\n", highest_rate);
    
    // Update band counters
    // Find band index
    int band_index = ((u8*)ptr_highest_band - (u8*)&(flow_table->meter_table.meter_entry[meter_index].bands)) / sizeof(struct ofp13_meter_band_drop);
    
    // Update counters
    flow_table->meter_table.band_stats_array[meter_index].band_stats[band_index].byte_band_count += bytes;
    flow_table->meter_table.band_stats_array[meter_index].band_stats[band_index].packet_band_count++;

    if(ptr_highest_band->type == OFPMBT13_DROP)
    {
        trace_printk(KERN_INFO "openflow_13.c: packet dropped\n");
        return METER_DROP;
    }
    else if(ptr_highest_band->type == OFPMBT13_DSCP_REMARK)
    {
        struct ofp13_meter_band_dscp_remark *ptr_dscp_band = (struct ofp13_meter_band_dscp_remark*)ptr_highest_band;
        int prec_increase = (int)(ptr_dscp_band->prec_level);
        
        trace_printk(KERN_INFO "openflow_13.c: DSCP drop precedence needs to be increased by %d", prec_increase);
        return prec_increase;
    }
 
    trace_printk(KERN_INFO "openflow_13.c: ERROR - unknown band type");
    return METER_NOACT;
}


/*
*   Retrieve number of flows bound to the specified meter
*
*   @param  id      - meter ID to check
*
*   @ret    count   - number of associated flows
*
*/
uint32_t get_bound_flows(uint32_t id)
{
    uint32_t count = 0;
    
    // Loop through flows
    for (int i=0;i<flow_table->iLastFlow;i++)
    {
        struct ofp13_instruction *inst_ptr;
        void *insts[8] = {0};
        int inst_size = 0;
        while(inst_size < flow_table->ofp13_oxm[i].inst_size){
            inst_ptr = (u8*)&flow_table->ofp13_oxm[i].inst + inst_size;
            insts[ntohs(inst_ptr->type)] = inst_ptr;
            inst_size += ntohs(inst_ptr->len);
        }
        
        // Check if metering instruction is present
        if(insts[OFPIT13_METER] != NULL)
        {
            struct ofp13_instruction_meter *inst_meter = insts[OFPIT13_METER];
            // Check the found meter id
            if(ntohl(inst_meter->meter_id) == id)
            {
                // The flow's instruction matches the specified meter id
                count++;    // increment the counter
            }
        }
    }
    
    return count;
}

/*
*   OpenFlow house keeping timer function.
*
*/
void nnOF_timer(void)
{
    return;
}
