/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#include <linux/types.h>
#include "openflow_spec.h"

#define MAX_FLOWS_13    512
#define MAX_TABLES      16
#define SHARED_BUFFER_LEN 16384
#define PACKET_BUFFER 32
#define PACKET_BUFFER_SIZE 256
#define MAX_OUTPUTS      65

#define MAX_METER_13        8   // Maximum number of meter entries in meter table
#define MAX_METER_BANDS_13  3   // Maximum number of meter bands per meter
#define POLICING_SAMPLES    20  // Sample for rate limiter
#define POLICING_SLICE      2   // time (ms) slice for each sample
#define METER_PARTIAL   8       // Meter structure length, excluding header and bands
#define METER_CAL_PPS   1   // Meter calibration value - PPS
#define METER_CAL_KBPS  1   // Meter calibration value - KBPS

/* Meter processing defines */
#define METER_DROP  -1  // drop packet
#define METER_NOACT 0   // no action
#define MAX_GROUPS 8
#define MAX_BUCKETS 8

#define ETH_PORT_NO 65

#define PB_EMPTY 0
#define PB_PACKETIN 1
#define PB_PACKETOUT 2
#define PB_PENDING 3

// nnOpenflow return codes
#define PORT_DROP       0xFFFFFF00

struct flows_counter
{
    u64 hitCount;
    u64 bytes;
    u32 duration;
    u8 active;
    int lastmatch;
};

struct table_counter
{
    u64 lookup_count;
    u64 matched_count;
    u64 byte_count;
};

struct oxm_header13
{
    u16 oxm_class;
    u8 oxm_field;
    u8 oxm_len;
};

struct ofp13_oxm
{
    u8 match[128];
    u8 inst[1100];
    u16 match_size;
    u16 inst_size;
};

struct group_table {
    int active;
    u8 type;
    u8 pad;
    u32 group_id;
    u8 bucket_id;
    u64 packet_count;
    u64 byte_count;
    int time_added;
};

struct action_bucket {
    int active;
    u64 packet_count;
    u64 byte_count;
    u8 data[1100];
};

/*
 *  OpenFlow meter entry structure
 *      Meter table is populated with these entries.
 *      The structure contains:
 *          - meter ID
 *          - counters
 *          - meter bands
 */
struct meter_entry13
{
    u32    meter_id;
    u32    flow_count;         // Number of flows bound to meter
    u64    packet_in_count;    // Packets processed by meter
    u64    byte_in_count;      // Bytes processed by meter
    u32    time_added;         // Time meter was added in ms (time alive calculated when required)
    u16    flags;              // Meter configuration flags
    u16    band_count;         // Number of bands in this meter
    time_t    last_packet_in;     // Time when meter last processed a packet (milliseconds)
    u8 active;             // Set if entry is valid
    struct ofp13_meter_band_drop bands[MAX_METER_BANDS_13];  // Meter bands
};

/*
 *  Meter band counters
 *      Each instance of meter_band_stats_array contains
 *      statistics for the maximum number of supported
 *      bands.
 *
 */
struct meter_band_stats_array
{
    struct ofp13_meter_band_stats band_stats[MAX_METER_BANDS_13];
};

struct policing_sample
{
    u32    packet_time;    // (time) when sampled
    u16    byte_count;     // Number of bytes during this sample
    u16    packet_count;   // Number of packets during this sample
};

struct meter_sample_array
{
    u16    sample_index;
    struct      policing_sample sample[POLICING_SAMPLES];
};

struct meter_table
{
    int iLastMeter;
    struct meter_entry13           meter_entry[MAX_METER_13];
    struct meter_band_stats_array   band_stats_array[MAX_METER_13];
};

struct flow_table
{
    int iLastFlow;
    int enabled;
    int auth_bypass;
    int port_status[ETH_PORT_NO];
    struct ofp13_flow_mod   flow_match13[MAX_FLOWS_13];
    struct ofp13_oxm        ofp13_oxm[MAX_FLOWS_13];
    struct flows_counter    flow_counters[MAX_FLOWS_13];
    struct ofp13_port_stats phys13_port_stats[ETH_PORT_NO];
    struct table_counter    table_counters[MAX_TABLES];
    struct group_table      group_table[MAX_GROUPS];
    struct action_bucket    action_buckets[MAX_BUCKETS];
    struct meter_table      meter_table;
};

struct packet_buffer
{
    u8 type;
    u8 age;
    u16 size;
    u32 inport;
    u8 reason;
    u8 flow;
    u8 table_id;
    u32 outport;
    struct net_device *dev;
    struct sk_buff *skb;
    u8 buffer[PACKET_BUFFER_SIZE];
};

struct packet_out
{
    u32 inport;
    u32 outport;
    struct sk_buff *skb; 
    struct net_device *dev;
};

struct output_list
{
    u32 outport[MAX_OUTPUTS];
    struct sk_buff *skb[MAX_OUTPUTS]; 
    struct net_device *dev[MAX_OUTPUTS];
};

struct pbuffer
{
    struct packet_buffer buffer[PACKET_BUFFER];
};

void nnOpenflow(u32 in_port, struct sk_buff *skb, struct net_device *dev, struct output_list *output_list);
struct packet_out nnPacketout(int buffer_id);

