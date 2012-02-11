#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <arpa/inet.h>
#endif

#include "common.h"
#include "mem.h"
#include "module_manage.h"
#include "log.h"
#include "helper.h"
#include "sys.h"
#include "conf.h"
#include "parser.h"
#include "process.h"
#include "decap.h"

#define PKTS_MAX_NUM 10
#define PKTS_MAX_LEN MAX_PACKET_LEN

static int32_t decap_init_global(module_info_t *this);
static int32_t decap_init_local(module_info_t *this, uint32_t thread_id);
static int32_t decap_process(module_info_t *this, void *data);
static int decap_fini_global(module_info_t *this);
static int decap_fini_local(module_info_t *this, uint32_t thread_id);

static uint16_t ipv4_frag_tag;
static uint16_t tcp_tag;
static uint16_t udp_tag;

typedef struct decap_stats {
	uint64_t ipv4_frag_pkts;
	uint64_t ipv6_frag_pkts;
	uint64_t ipv6_pkts;
	uint64_t icmp_pkts;
	uint64_t arp_pkts;
	uint64_t malformed_pkts;
	uint64_t tcp_pkts;
	uint64_t udp_pkts;
	uint64_t unknown_pkts;
} decap_stats_t;

enum {
	UNHANDLE_PKTS = 100,
	UNKNOWN_PKTS,
	MALFORMED_PKTS,
} cap_code;

typedef struct info_global {
    mutex_t lock;
    decap_stats_t stats;
} info_global_t;

typedef struct info_local {
	packet_t *packet;
	decap_stats_t stats;
	struct cap_info {
		uint8_t pkts_cap[PKTS_MAX_LEN];
		uint32_t pkts_len;
		uint32_t code;
	} cap_pkts[PKTS_MAX_NUM];
	uint8_t cap_num;
} info_local_t;

module_ops_t decap_mod_ops = {
    .init_global = decap_init_global,
	.init_local = decap_init_local,
	.start = NULL,
	.process = decap_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = decap_fini_global,
	.fini_local = decap_fini_local,
};

static inline void __pkts_cap(info_local_t *info, uint32_t code)
{
	if (info->cap_num < PKTS_MAX_NUM) {
		memcpy(info->cap_pkts[info->cap_num].pkts_cap, info->packet->data, info->packet->len);
		info->cap_pkts[info->cap_num].pkts_len = info->packet->len;
		info->cap_pkts[info->cap_num].code = code;
		info->cap_num++;
	}
}

static inline void __pkts_dump(info_local_t *info)
{
	int i;
	for (i=0; i<info->cap_num; i++) {
		log_print(syslog_p, "--------------------code:%d-------------------\n", info->cap_pkts[i].code);
		list_format_print_buffer(syslog_p,
								 info->cap_pkts[i].pkts_cap, 8,
								 info->cap_pkts[i].pkts_len, FORMAT_PRINT_WITH_HEAD);
		log_print(syslog_p, "\n");
	}
}

static int32_t decap_init_global(module_info_t *this)
{
    info_global_t *gp;
    ipv4_frag_tag = tag_id_get_from_name(pktag_hd_p, "ipv4_frag");
	tcp_tag = tag_id_get_from_name(pktag_hd_p, "tcp");
	udp_tag = tag_id_get_from_name(pktag_hd_p, "udp");

    gp = zmalloc(info_global_t *, sizeof(info_global_t));
    assert(gp);

    this->pub_rep = gp;
    return mutex_init(&gp->lock, NULL);
}

static int32_t decap_init_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *info = zmalloc(info_local_t *, sizeof(info_local_t));
	assert(info);
    module_priv_rep_set(this, thread_id, (void *)info);
    return 0;
}

static int32_t decap_process(module_info_t *this, void *data)
{
	packet_t *packet = (packet_t *)data;
	void *ptr = packet->data;
	void *start_ptr = ptr;
	uint16_t tag;
	dpi_ether_hdr_t *ether;
    dpi_vlan_hdr_t *vlan;
    dpi_mpls_hdr_t *mpls;
    dpi_ipv4_hdr_t *ipv4;
    dpi_tcp_hdr_t *tcp;
	int vlan_layer;
	int mpls_layer;
	uint16_t ether_type;
	uint8_t first_nibble;
	info_local_t *info;
	decap_stats_t *stats;
	uint8_t ip_protocol;

    info = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());
    assert(info);
    stats = &info->stats;
	switch (packet->prot_types[packet->prot_depth-1]) {
	case DPI_PROT_ETHER:
        goto do_decap_ether;
    case DPI_PROT_IPV4:
        goto do_decap_ipv4;
    case DPI_PROT_IPV6:
        goto do_decap_ipv6;
	default:
		goto unknown_pkts;
	}

do_decap_ether:
	info->packet = packet;
	ether =  (dpi_ether_hdr_t *)ptr;
	ptr += sizeof(dpi_ether_hdr_t);
	ether_type = ntohs(ether->type);
	vlan_layer = 0;

	while ((ether_type == DPI_ETHTYPE_VLAN) || (ether_type == DPI_ETHTYPE_VLAN2)) {
        vlan = (dpi_vlan_hdr_t *)ptr;
        ptr += sizeof(dpi_vlan_hdr_t);
        ether_type = ntohs(vlan->type);
        vlan_layer++;
        packet->prot_types[packet->prot_depth-1]++;
        if ( vlan_layer == 4 ) {
            break;
        }
    }
	switch (ether_type) {
	case DPI_ETHTYPE_IPV4:
		packet->prot_types[packet->prot_depth] = DPI_PROT_IPV4;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv4;
    case DPI_ETHTYPE_IPV6:
        packet->prot_types[packet->prot_depth] = DPI_PROT_IPV6;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv6;
	case DPI_ETHTYPE_ARP:
		stats->arp_pkts++;
		goto do_decap_unhandle;
    case DPI_ETHTYPE_MPLS:
        packet->prot_types[packet->prot_depth] = DPI_PROT_MPLS1;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_mpls;
	default:
		goto unknown_pkts;
    }

do_decap_mpls:
	mpls_layer = 0;
    while (1) {
        mpls = (dpi_mpls_hdr_t *)ptr;
        ptr += sizeof(dpi_mpls_hdr_t);
        mpls_layer++;
        packet->prot_types[ packet->prot_depth - 1 ]++;
        if ( mpls->s ) {
            break;
        }
        if ( mpls_layer == 8 ) {
        }
    }
	first_nibble = ( ( uint8_t * )ptr )[ 0 ] >> 4;
    switch ( first_nibble ) {
    case 4:
        packet->prot_types[packet->prot_depth] = DPI_PROT_IPV4;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv4;
    case 6:
        packet->prot_types[packet->prot_depth] = DPI_PROT_IPV6;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv6;
	default:
		goto unknown_pkts;
    }
do_decap_ipv4:
	ipv4 = (dpi_ipv4_hdr_t *)ptr;
	if ((htons(ipv4->offset) & IP_FRAGMASK) != 0) {
        stats->ipv4_frag_pkts++;
		tag = ipv4_frag_tag;
		packet->pktag = tag;
		return tag;
    }
	ptr += ipv4->hdr_len * 4;
	ip_protocol = ipv4->protocol;
	packet->real_applen = ntohs(ipv4->length) - ipv4->hdr_len * 4;
	packet->app_type = INVALID_PROTO_ID;
	switch (ip_protocol) {
	case DPI_IPPROT_ICMP:
        packet->prot_types[packet->prot_depth] = DPI_PROT_ICMP;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_icmp;
	case DPI_IPPROT_TCP:
        packet->prot_types[packet->prot_depth] = DPI_PROT_TCP;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_tcp;
	case DPI_IPPROT_UDP:
        packet->prot_types[ packet->prot_depth ] = DPI_PROT_UDP;
        packet->prot_offsets[ packet->prot_depth ] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_udp;
	default:
		goto unknown_pkts;
	}
do_decap_tcp:
	tcp = (dpi_tcp_hdr_t *)ptr;
    ptr += tcp->hdr_len * 4;
	packet->app_offset = ptr - start_ptr;
	packet->real_applen -= tcp->hdr_len * 4;
	if (packet->app_offset <= packet->len){
		stats->tcp_pkts++;
		tag = tcp_tag;
		packet->pktag = tag;
		return tag;
    } else {
		__pkts_cap(info, MALFORMED_PKTS);
		stats->malformed_pkts++;
		packet->pktag = 0;
		return 0;
	}
do_decap_udp:
    ptr += sizeof(dpi_udp_hdr_t);
	packet->app_offset = ptr - start_ptr;
	packet->real_applen -= sizeof(dpi_udp_hdr_t);
	if (packet->app_offset <= packet->len){
		stats->udp_pkts++;
		tag = udp_tag;
		packet->pktag = tag;
        return tag;
    } else {
		__pkts_cap(info, MALFORMED_PKTS);
		stats->malformed_pkts++;
		packet->pktag = 0;
        TRACE;
		return 0;
	}
do_decap_icmp:
	//__pkts_cap(info, DPI_PROT_ICMP);

	packet->pktag = 0;
	stats->icmp_pkts++;
	return 0;
do_decap_ipv6:
	//__pkts_cap(info, DPI_PROT_IPV6);
	packet->pktag = 0;
	stats->ipv6_pkts++;
	return 0;
do_decap_unhandle:
	//__pkts_cap(info, UNHANDLE_PKTS);
	packet->pktag = 0;
	return 0;
unknown_pkts:
	__pkts_cap(info, UNKNOWN_PKTS);
	packet->pktag = 0;
	stats->unknown_pkts++;
	return 0;
}

static int decap_fini_global(module_info_t *this)
{
    info_global_t *info;
	decap_stats_t *stats;

    info = (info_global_t *)this->pub_rep;
    stats = &info->stats;

	log_notice(syslog_p, "\n------------------decapinfo---------------\n");
	log_notice(syslog_p, "ipv4_frag_pkts=%llu\n", stats->ipv4_frag_pkts);
	log_notice(syslog_p, "ipv6_frag_pkts=%llu\n", stats->ipv6_frag_pkts);
	log_notice(syslog_p, "ipv6_pkts=%llu\n", stats->ipv6_pkts);
	log_notice(syslog_p, "icmp_pkts=%llu\n", stats->icmp_pkts);
	log_notice(syslog_p, "arp_pkts=%llu\n", stats->arp_pkts);
	log_notice(syslog_p, "tcp_pkts=%llu\n", stats->tcp_pkts);
	log_notice(syslog_p, "udp_pkts=%llu\n", stats->udp_pkts);
	log_notice(syslog_p, "malformed_pkts=%llu\n", stats->malformed_pkts);
	log_notice(syslog_p, "unknown_pkts=%llu\n", stats->unknown_pkts);

    free(info);
    return 0;
}

static int32_t decap_fini_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *lp;
    info_global_t *gp;

    lp = (info_local_t *)module_priv_rep_get(this, thread_id);
    gp = (info_global_t *)this->pub_rep;

    TRACE;
    mutex_lock(&gp->lock);
    TRACE;
	log_notice(syslog_p, "\ncore %d--------------decap packet info---------------\n", thread_id);
	__pkts_dump(lp);
	log_notice(syslog_p, "\n");

    gp->stats.ipv4_frag_pkts += lp->stats.ipv4_frag_pkts;
    gp->stats.ipv6_frag_pkts += lp->stats.ipv6_frag_pkts;
    gp->stats.ipv6_pkts += lp->stats.ipv6_pkts;
    gp->stats.icmp_pkts += lp->stats.icmp_pkts;
    gp->stats.arp_pkts += lp->stats.arp_pkts;
    gp->stats.tcp_pkts += lp->stats.tcp_pkts;
    gp->stats.udp_pkts += lp->stats.udp_pkts;
    gp->stats.malformed_pkts += lp->stats.malformed_pkts;
    gp->stats.unknown_pkts += lp->stats.unknown_pkts;

    mutex_unlock(&gp->lock);

	free(lp);
    return 0;
}
