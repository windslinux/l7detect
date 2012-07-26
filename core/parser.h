#ifndef __PARSER_H__
#define __PARSER_H__

#include "common.h"
#include "meta_buf.h"

#define MAX_PACKET_LEN 1518
#define MAX_PARSER_DEPTH 10

typedef struct packet {
	void *top_packet;
    void *next_packet;
    meta_hd_t *meta_hd;/*该包对应的元数据头*/
	uint64_t dir:2;
#define PKT_DIR_UPSTREAM 0x1
#define PKT_DIR_DNSTREAM 0x2
#define PKT_DIR_MASK 0x3
#define PKT_DEBUG 0x1000000000000000
#define PKT_HANDLE_MASK 0xf0ull
#define PKT_DONT_FREE 0x10ull
#define PKT_LOOP_NEXT 0x20ull
    uint64_t flag:62;/*其他标志*/
	uint32_t pktag;
	uint8_t prot_types[MAX_PARSER_DEPTH];
    uint8_t prot_offsets[MAX_PARSER_DEPTH];
    uint8_t prot_depth;
	uint8_t app_offset;
    uint16_t app_type;
	uint32_t len;
	uint32_t real_applen;/*去除掉pad以后剩余的真正app的长度*/
	uint8_t *data;
} packet_t;

typedef struct {
    uint8_t dst_mac[ 6 ];
    uint8_t src_mac[ 6 ];
    uint16_t type;
} dpi_ether_hdr_t;

typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
	uint16_t pri        : 3;
	uint16_t cfi        : 1;
	uint16_t vlan_id    : 12;
#elif BYTE_ORDER == LITTLE_ENDIAN
	uint16_t vlan_id    : 12;
	uint16_t cfi        : 1;
	uint16_t pri        : 3;
#endif
	uint16_t type;
} dpi_vlan_hdr_t;

typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t ttl    : 8;
    uint32_t s      : 1;
    uint32_t exp    : 3;
    uint32_t label  : 20;
#elif BYTE_ORDER == LITTLE_ENDIAN
    uint32_t label  : 20;
    uint32_t exp    : 3;
    uint32_t s      : 1;
    uint32_t ttl    : 8;
#endif
} dpi_mpls_hdr_t;

typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t version : 4;
	uint8_t hdr_len : 4;
#elif BYTE_ORDER == LITTLE_ENDIAN
	uint8_t hdr_len : 4;
	uint8_t version : 4;
#endif
	uint8_t tos;
	uint16_t length;
	uint16_t id;
	uint16_t offset;
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_FRAGMASK 0x3fff      /* mask for judge if ip has fragment bits*/
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
} dpi_ipv4_hdr_t;

typedef struct {
#if BYTE_ORDER == BIG_ENDIAN
    uint32_t version : 4;
    uint32_t traffic_class : 8;
    uint32_t flow_label : 20;
#elif BYTE_ORDER == LITTLE_ENDIAN
    uint32_t flow_label : 20;
    uint32_t traffic_class : 8;
    uint32_t version : 4;
#endif
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint64_t sip_high;
    uint64_t sip_low;
    uint64_t dip_high;
    uint64_t dip_low;
} dpi_ipv6_hdr_t;

typedef struct {
    uint8_t next_header;
    uint8_t hdr_ext_len;
} dpi_ipv6_ext_hdr_t;

typedef struct {
    uint8_t next_header;
    uint8_t reserved;
#if BYTE_ORDER == BIG_ENDIAN
    uint16_t frag_offset : 13;
    uint16_t reserved_flag : 2;
    uint16_t mf_flag : 1;
#elif BYTE_ORDER == LITTLE_ENDIAN
    uint16_t mf_flag : 1;
    uint16_t reserved_flag : 2;
    uint16_t frag_offset : 13;
#endif
    uint32_t id;
} dpi_ipv6_frag_hdr_t;

typedef struct  {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t hdr_len : 4;
	uint8_t reserved1 : 4;
#elif BYTE_ORDER == LITTLE_ENDIAN
	uint8_t reserved1 : 4;
	uint8_t hdr_len : 4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t reserved2 : 2;
	uint8_t f_urg : 1;
	uint8_t f_ack : 1;
	uint8_t f_psh : 1;
	uint8_t f_rst : 1;
	uint8_t f_syn : 1;
	uint8_t f_fin : 1;
#elif BYTE_ORDER == LITTLE_ENDIAN
	uint8_t f_fin : 1;
	uint8_t f_syn : 1;
	uint8_t f_rst : 1;
	uint8_t f_psh : 1;
	uint8_t f_ack : 1;
	uint8_t f_urg : 1;
	uint8_t reserved2 : 2;
#endif
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urg_ptr;
} dpi_tcp_hdr_t;

typedef struct {
    uint8_t  i_type;
    uint8_t  i_code;
    uint16_t i_checksum;
    uint16_t i_id;
    uint16_t i_seq;
    uint32_t timestamp;
}dpi_icmp_hdr_t;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
} dpi_udp_hdr_t;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
} dpi_l4_hdr_t;


#endif
