/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#include <linux/types.h>
#include <stdbool.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

struct packet_fields
{
    bool parsed;
    bool isVlanTag;
    u8 *payload;
    u16 eth_prot;
    u8 ip_prot;
    u16 arp_op;
    u32 arp_spa;
    u32 arp_tpa;
    u8 arp_sha[6];
    u8 arp_tha[6];    
    u16 vlanid;
    u32 ip_src;
    u32 ip_dst;
    // transport layer
    u16 tp_src;
    u16 tp_dst;
};

void nnOF13_tablelookup(struct sk_buff *skb, struct net_device *dev, int port, struct output_list *output_list);
void nnOF_timer(void);
