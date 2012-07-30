#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <dlfcn.h>
#include "plugin.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "event.h"
#endif

#include "common.h"
#include "mem.h"
#include "module_manage.h"
#include "sys.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"
#include "hash_table.h"
#include "decap.h"
#include "ff_table.h"

#define INC_CNT(count) count++

static int32_t session_frm_init_global(module_info_t *this);
static int32_t session_frm_init_local(module_info_t *this, uint32_t thread_id);
static int32_t session_frm_process(module_info_t *this, void *data);
static void* session_frm_result_get(module_info_t *this);
static void session_frm_result_free(module_info_t *this);
static int session_frm_fini_global(module_info_t *this);
static int session_frm_fini_local(module_info_t *this, uint32_t thread_id);

static uint16_t sf_plugin_tag;
static uint16_t parsed_tag;
static uint16_t session_buf_tag;
static uint16_t next_stage_tag; /*未来扩展使用*/

module_ops_t session_frm_ops = {
	.init_global = session_frm_init_global,
	.init_local = session_frm_init_local,
    .start = NULL,
	.process = session_frm_process,
	.result_get = session_frm_result_get,
	.result_free = session_frm_result_free,
	.fini_global = session_frm_fini_global,
    .fini_local = session_frm_fini_local,
};

typedef struct session_frm_stats {
	uint64_t unknown_pkts;
	uint64_t unknown_dir;
	uint64_t session_count;
	uint64_t session_failed;
} session_frm_stats_t;

typedef struct flow_item {
	uint32_t pkts;
	uint32_t bytes;
} flow_item_t;

typedef struct session_index {
	uint32_t ip[2];
	uint16_t port[2];
	uint32_t protocol:8;
	uint32_t hash:24;
} session_index_t;

struct session_item {
	session_index_t index;
	flow_item_t flow[2];		/**< [0]为上行流，[1]为下行流 */
    packet_t *packet;           /**< 包缓存，用来处理dirty的情况*/
    ff_item_t *sub_ff;
#define FLOW_UP_STREAM_INDEX 0
#define FLOW_DN_STREAM_INDEX 1
	uint16_t dir:2;
#define SESSION_INDEX_UPSTREAM PKT_DIR_UPSTREAM
#define SESSION_INDEX_DNSTREAM PKT_DIR_DNSTREAM
#define SESSION_DIR_MASK 0x3
#define SESSION_DIRTY 0x10
#define SESSION_NO_TIMEOUT 0x20
	uint16_t flag:14;
	uint16_t stage;
    uint16_t engine_id;
	uint16_t reserved;
	sys_time_t start_time;
	sys_time_t last_time;
	uint32_t app_type;			/**<  协议小类*/
	uint32_t app_state;         /**< 协议识别状态*/
	list_head_t protobuf_head;
};

typedef uint32_t (*hash_func)(session_index_t *info);

typedef struct info_global {
    mutex_t lock;
    session_frm_stats_t stats;
    session_conf_t *conf;
	sf_proto_conf_t *sf_conf;
	hash_table_hd_t *session_table;
	hash_table_hd_t *ff_table;
	log_t *log_c;
    struct {
        pthread_t tid;
        struct event_base *base;
        struct event ev;
        struct timeval tv;
        uint32_t bucket;
    } timer;
	hash_func hash_cb;
} info_global_t;

typedef struct info_local {
	packet_t *packet;
	session_item_t *session;	    /**< 流表中找到的表项*/
    ff_item_t *ff_item;
	session_index_t index_cache;	/**< 临时的session cache，减小每次进入函数堆栈分配的开销 */
	session_frm_stats_t stats;
	proto_comm_t proto_buf;        /**< 用于处理时传递上一次的数据给sf_plugin */
} info_local_t;

typedef struct hash_map {
	char *name;
	hash_func hash_cb;
} hash_map_t;

static void __print_item(info_global_t *info, session_item_t *item);
static int32_t __free_item(hash_table_hd_t *session_table, hash_table_hd_t *ff_table,
                            uint32_t hash, session_item_t *item);

static uint32_t hash_xor(session_index_t *index)
{
	return index->ip[0] ^ index->ip[1] ^ index->port[0] ^ index->port[1];
}

static uint32_t hash_xor_sum(session_index_t *index)
{
	return (index->ip[0] ^ index->ip[1]) + (index->port[0] ^ index->port[1]);
}

static uint32_t hash_sum(session_index_t *index)
{
	return (index->ip[0] + index->ip[1]) + (index->port[0] + index->port[1]);
}

static void __flow_timer_process(evutil_socket_t fd, short which, void *arg)
{
    info_global_t *info;
    hash_table_hd_t *hd, *ff_hd;
    ff_item_t *ff_item;
    session_item_t *item;
    session_conf_t *conf;
    struct timeval current;
    int32_t status;

    info = (info_global_t *)arg;
    hd = info->session_table;
    ff_hd = info->ff_table;
    conf = info->conf;
    sys_get_time(&current);

    hash_table_lock(hd, info->timer.bucket, 0);
    hash_table_one_bucket_for_each(hd, info->timer.bucket, item) {
        if (sys_time_diff(item->last_time, current) >= conf->session_expire_time) {
            if ((item->flag & SESSION_DIRTY) || (item->flag & SESSION_NO_TIMEOUT)) {
                continue;
            }
            assert(item->packet == NULL);
            __print_item(info, item);
            log_info(syslog_p, "timer item %p, last_sec=%d, current=%d\n", item, item->last_time.tv_sec, current.tv_sec);
            if ((status = __free_item(hd, info->ff_table, info->timer.bucket, item)) != 0) {
                log_error(syslog_p, "free item error, status %d\n", status);
            }
        } else {
            ff_item = item->sub_ff;
            while (ff_item) {
                uint32_t ip, ff_hash;
                uint16_t port;
                int32_t rv;

                ff_item_t *current_item = ff_item;
                ff_item = ff_item->next;
                /*这里没有加锁就访问了，但在推出前，timer线程已经结束，这个时候剩余的ff_item将在session_clear中删除，因此是没有问题的*/
                ip = current_item->ip;
                port = current_item->port;
                ff_hash = ff_table_hash(ff_hd, ip, port);
                ff_table_lock(ff_hd, ff_hash);
                if (sys_time_diff(ff_item->last_time, current) >= conf->session_expire_time) {
                    rv = ff_table_delete(ff_hd, ff_hash, current_item);
                    if (rv != 0) {
            		    log_error(syslog_p, "remove ff_item error, status %d\n", rv);
                    }
                    item->sub_ff = ff_item;
                }
                ff_table_unlock(ff_hd, ff_hash);
            }
        }
    }

    info->timer.bucket++;

    if (info->timer.bucket >= hd->bucket_num) {
        info->timer.bucket = 0;
    }

    int rv = evtimer_add(&info->timer.ev, &info->timer.tv);
    if (rv != 0) {
        log_error(syslog_p, "evtimer add error!\n");
    }
}

static void *__event_thread_cb(void *arg)
{
    info_global_t *info;
    int rv;

    info = (info_global_t *)arg;

    info->timer.base = event_base_new();
    assert(info->timer.base);

    rv = evtimer_assign(&info->timer.ev, info->timer.base, __flow_timer_process, info);
    assert(rv == 0);

    //rv = evtimer_add(&info->timer.ev, &info->timer.tv);
    rv = 0;
    assert(rv == 0);
    event_base_loop(info->timer.base, 0);
    return NULL;
}

void __update_session_count(session_item_t *session, packet_t *packet)
{
	uint32_t dir =  packet->dir & PKT_DIR_MASK;

    if (dir == PKT_DIR_UPSTREAM) {
		session->flow[FLOW_UP_STREAM_INDEX].pkts++;
		session->flow[FLOW_UP_STREAM_INDEX].bytes += packet->len;
	} else if (dir == PKT_DIR_DNSTREAM) {
		session->flow[FLOW_DN_STREAM_INDEX].pkts++;
		session->flow[FLOW_DN_STREAM_INDEX].bytes += packet->len;
	}
    sys_get_time(&session->last_time);
}

static inline int32_t __is_interal_ip(uint32_t ip)
{
	if (((ip & 0xff000000) == 0xa000000) || ((ip & 0xffff0000) == 0xc0a80000) ||
		((ip >= 0xac100000) && (ip <= 0xac1f0000))) {
		return 1;
	} else {
		return 0;
	}
}

static inline int32_t __session_index_dir(session_index_t *index)
{
	int32_t dir;
	int32_t internal_ip0, internal_ip1;

	internal_ip0 = __is_interal_ip(index->ip[0]);
	internal_ip1 = __is_interal_ip(index->ip[1]);

	if (internal_ip0 && !internal_ip1) {
		dir = PKT_DIR_UPSTREAM;
	} else if (internal_ip1 && !internal_ip0) {
		dir = PKT_DIR_DNSTREAM;
	} else if (index->port[0] < index->port[1]) {
		dir = PKT_DIR_DNSTREAM;
	} else {
		dir = PKT_DIR_UPSTREAM;
	}
	return dir;
}

static inline void __init_session(session_item_t *session, session_index_t *index, packet_t *packet)
{
	memset(session, 0, sizeof(session_item_t));
	memcpy(&session->index, index, sizeof(session_index_t));
	session->dir = __session_index_dir(index);
	session->app_type = INVALID_PROTO_ID;
    sys_get_time(&session->start_time);
	LIST_HEAD_INIT(&session->protobuf_head);
}
static inline void __clear_session(session_item_t *session)
{
    session->flag &= ~SESSION_DIRTY;
    session->packet = NULL;
}

static char *__get_ip_protocol_name(uint16_t protocol)
{
	switch(protocol) {
	case 1:
		return "icmp";
	case 6:
		return "tcp";
	case 17:
		return "udp";
	default:
		return "error";
		break;
	}
	return "error";
}

static void __print_item(info_global_t *info, session_item_t *item)
{
    uint32_t ip0_int, ip1_int;
	uint16_t port0, port1;
	char ip0[20], ip1[20];

    ip0_int = htonl(item->index.ip[0]);
	ip1_int = htonl(item->index.ip[1]);
	port0 = item->index.port[0];
	port1 = item->index.port[1];
	if (item->dir == SESSION_INDEX_DNSTREAM) {
	/*如果索引是下行的，交换一下ip和端口来展示*/
		swap(ip0_int, ip1_int);
		swap(port0, port1);
	}
	/*源ip，源端口，目的ip, 目的端口，协议类型，上行包数，下行包数，上行字节数，下行字节数*/
	log_print(info->log_c, "%s,%d,%s,%d,%s,%d,%d,%d,%d,%s\n",
			   inet_ntop(AF_INET, &ip0_int, ip0, sizeof(ip0)),
			   port0,
			   inet_ntop(AF_INET, &ip1_int, ip1, sizeof(ip1)),
			   port1,
			   __get_ip_protocol_name(item->index.protocol),
			  item->flow[0].pkts, item->flow[1].pkts,
			  item->flow[0].bytes, item->flow[1].bytes,
			  (item->app_type != INVALID_PROTO_ID) ?
			  info->sf_conf->protos[item->app_type].name:"Unknown");
}

static inline void __session_return_handle(info_local_t *this, packet_t *packet, session_item_t *session)
{
    /*处理会话中尚未被处理的其他数据包*/
    void *next_packet = NULL;
    next_packet = packet->next_packet;
    if (next_packet != NULL) {
        this->packet = next_packet;
        this->packet->pktag = session_buf_tag;
    } else {
        __clear_session(session);
        packet->pktag = next_stage_tag;
    }
}

static inline uint32_t __post_parsed(info_local_t *this, hash_table_hd_t *hd,
                                     hash_table_hd_t *ff_hd,
                                     proto_comm_t *comm,  uint32_t final_state)
{
    packet_t *packet;
    session_item_t* session;

    session = this->session;
    packet = this->packet;

    hash_table_lock(hd, session->index.hash, 0);
	session->app_type = packet->app_type;
	if (comm->state == final_state) {
		/*do some clean things*/
        session->flag &= ~ SESSION_NO_TIMEOUT;
		protobuf_destroy(&session->protobuf_head);
	} else {
		/*save status*/
        if (session->app_type != INVALID_PROTO_ID) {
            /*已经识别协议，在分析阶段*/
            meta_info_t *meta;
            meta = meta_buffer_item_get(packet->meta_hd, NULL, META_TYPE_FF);
            if (meta != NULL) {
                meta_ff_t *ff;
                ff_item_t *item;
                uint32_t hash;

                ff = (meta_ff_t *)meta_buffer_item_get_data(packet->meta_hd, meta);
                if (ff != NULL)  {
                    hash = ff_table_hash(ff_hd, ff->ip, ff->port);
                    ff_table_lock(ff_hd, hash);
                    item = ff_table_insert(ff_hd, session, hash, ff->ip, ff->port, ff->app_type);
                    if (item == NULL) {
                        log_error(syslog_p, "ff_table insert error!\n");
                    } else {
                        item->next = session->sub_ff;
                        session->sub_ff = item;
                    }
                    ff_table_unlock(ff_hd, hash);
                }
            }
            session->flag |= SESSION_NO_TIMEOUT;
        }
		session->app_state = comm->state;
        /*mask在sf_plugin模块中已经被修改*/
	}
    session->engine_id  = comm->engine_id;
    __session_return_handle(this, packet, session);
    hash_table_unlock(hd, session->index.hash, 0);
	return packet->pktag;
}


static int32_t __session_compare(void *this, void *user_data, void *item)
{
	session_item_t *table_item = (session_item_t *)item;

	if (memcmp(this, &table_item->index, sizeof(session_index_t)) == 0) {
		/*匹配*/
		return 0;
	}
	/*不匹配*/
	return 1;
}

static void __session_item_show(info_global_t *info, session_frm_stats_t *stats)
{
	hash_table_hd_t *session_table = info->session_table;
	uint32_t i;
	uint32_t bucket, max_bucket = 0;

	log_notice(syslog_p, "\n-----------------sessioninfo---------------\n");
    log_notice(syslog_p, "unknown_pkts=%llu\n", stats->unknown_pkts);
    log_notice(syslog_p, "unknown_dir=%llu\n", stats->unknown_dir);
    log_notice(syslog_p, "session_count=%llu\n", stats->session_count);
	log_notice(syslog_p, "session_failed=%llu\n", stats->session_failed);


	for (i=0; i<session_table->bucket_num; i++) {
		session_item_t *item = NULL;
		bucket = 0;
		hash_table_lock(session_table, i, 0);
		hash_table_one_bucket_for_each(session_table, i, item) {
            __print_item(info, item);
			bucket++;
        }
		hash_table_unlock(session_table, i, 0);
		if (bucket > max_bucket) {
			max_bucket = bucket;
		}
	}
	log_notice(syslog_p, "max_bucket=%d\n", max_bucket);
}

static int32_t __free_item(hash_table_hd_t *session_table, hash_table_hd_t *ff_table,
                            uint32_t hash, session_item_t *item)
{
    int32_t status;
    ff_item_t *ff_item;

    status = hash_table_remove(session_table, hash, item);
	if (status != 0) {
        return status;
	}

    ff_item = item->sub_ff;
    while (ff_item) {
        uint32_t ip, ff_hash;
        uint16_t port;
        int32_t rv;

        ff_item_t *current = ff_item;
        ff_item = ff_item->next;
        /*这里没有加锁就访问了，必须要保证ff_item只能在这里删除*/
        ip = current->ip;
        port = current->port;
        ff_hash = ff_table_hash(ff_table, ip, port);
        ff_table_lock(ff_table, ff_hash);

        rv = ff_table_delete(ff_table, ff_hash, current);
        if (rv != 0) {
		    log_error(syslog_p, "remove ff_item error, status %d\n", rv);
        }
        item->sub_ff = ff_item;
        ff_table_unlock(ff_table, ff_hash);
    }
	protobuf_destroy(&item->protobuf_head);
	free(item);
    return 0;
}

static void __session_table_clear(hash_table_hd_t *session_table, hash_table_hd_t *ff_table)
{
	uint32_t i;
	int32_t status;

	for (i=0; i<session_table->bucket_num; i++) {
		session_item_t *item = NULL;
		hash_table_lock(session_table, i, 0);
		hash_table_one_bucket_for_each(session_table, i, item) {
			if (item) {
                if ((status = __free_item(session_table, ff_table, i, item)) != 0) {
		            log_error(syslog_p, "remove item error, status %d\n", status);
                }
            }
		}
		hash_table_unlock(session_table, i, 0);
	}
}


static int32_t session_frm_init_global(module_info_t *this)
{
    info_global_t *info;
    session_conf_t *conf;
	sf_proto_conf_t *sf_conf;
    hash_table_hd_t *session_table, *ff_table;
	uint32_t i;
    int rv;

	hash_map_t hash_map[] = {
		{"hash_xor", hash_xor},
		{"hash_xor_sum", hash_xor_sum},
		{"hash_sum", hash_sum},
	};

	assert(sizeof(session_item_t) <= 128);
    info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	conf = (session_conf_t *)conf_module_config_search(SESSION_CONF_NAME, NULL);
    mutex_init(&info->lock, NULL);
	assert(conf);

	sf_conf = (sf_proto_conf_t *)conf_module_config_search(SF_PROTO_CONF_NAME, NULL);
	assert(sf_conf);

	session_table = hash_table_init(conf->bucket_num, SPINLOCK);
	assert(session_table);

    ff_table = ff_table_init(conf->ff_bucket_num);
    assert(ff_table);

    info->session_table = session_table;
    info->ff_table = ff_table;
    info->conf = conf;
    info->sf_conf = sf_conf;

	info->log_c = log_init(conf->session_logname, DEBUG);
	assert(info->log_c);

	log_print(info->log_c, "源IP, 源端口, 目的IP, 目的端口, 协议类型, 上行包数, 下行包数, 上行字节数, 下行字节数, 协议类型\n");
	for(i=0; i<sizeof(hash_map)/sizeof(hash_map[0]); i++) {
		if (strcmp(hash_map[i].name, conf->hash_name) == 0) {
			info->hash_cb = hash_map[i].hash_cb;
			break;
		}
	}

	assert(info->hash_cb);

    info->timer.tv.tv_sec = 0;
    info->timer.tv.tv_usec = 100;

    rv = pthread_create(&info->timer.tid, NULL, __event_thread_cb, info);
    assert(rv == 0);

    this->pub_rep = info;

    sf_plugin_tag = tag_id_get_from_name(pktag_hd_p, "sf_plugin");
	parsed_tag = tag_id_get_from_name(pktag_hd_p, "parsed");
    session_buf_tag = tag_id_get_from_name(pktag_hd_p, "session_buf");
    return 0;
}


static int32_t session_frm_init_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *info;
    info = zmalloc(info_local_t *, sizeof(info_local_t));

    module_priv_rep_set(this, thread_id, (void *)info);
    return 0;
}

static int32_t session_frm_process(module_info_t *this, void *data)
{
	packet_t *packet;
    info_global_t *gp;
    info_local_t *lp;
	session_frm_stats_t *stats;
	dpi_ipv4_hdr_t *iphdr;
	dpi_l4_hdr_t *l4hdr;
	session_item_t *session;
	session_index_t *buf;
	hash_table_hd_t *hd;
	uint32_t hash;
    meta_tuple_info_t tuple_info;
    meta_info_t *m_info;

	uint8_t swap_flag = 0;
	int32_t status;
	proto_comm_t *comm = NULL;

    gp = (info_global_t *)this->pub_rep;
    lp = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());

	hd = gp->session_table;
	stats = &lp->stats;
	session = lp->session;
	buf = &lp->index_cache;

	if ((lp->packet != NULL) && lp->packet != data) {
		comm = (proto_comm_t *)data;
		packet = comm->packet;
		assert(packet == lp->packet);
	} else {
		packet = (packet_t *)data;
	}

	lp->packet = packet;

	if (packet->pktag == parsed_tag) {
		assert(comm);
		return __post_parsed(lp, hd, gp->ff_table, comm, gp->sf_conf->final_state);
	}

	if (!(packet->prot_types[packet->prot_depth-2] == DPI_PROT_IPV4)) {
		return -UNKNOWN_PKT;
	} else {
		uint8_t last_prot = packet->prot_types[packet->prot_depth-1];
		if ((last_prot != DPI_PROT_TCP) && (last_prot != DPI_PROT_UDP) &&
			(last_prot != DPI_PROT_ICMP)) {
			return -UNKNOWN_PKT;
		}
	}
	iphdr = (dpi_ipv4_hdr_t *)((void *)packet->data + packet->prot_offsets[packet->prot_depth-2]);
	l4hdr = (dpi_l4_hdr_t *)((void *)packet->data + packet->prot_offsets[packet->prot_depth-1]);
	buf->ip[0] = ntohl(iphdr->src_ip);
	buf->ip[1] = ntohl(iphdr->dst_ip);
	buf->port[0] = ntohs(l4hdr->src_port);
	buf->port[1] = ntohs(l4hdr->dst_port);
	buf->protocol = iphdr->protocol;
    m_info = meta_buffer_item_get(packet->meta_hd, NULL, META_TYPE_TUPLE_INFO);
    if (m_info == NULL) {
        tuple_info.sip = buf->ip[0];
        tuple_info.dip = buf->ip[1];
        tuple_info.sport = buf->port[0];
        tuple_info.dport = buf->port[1];
        tuple_info.protocol = buf->protocol;
    }

	if (buf->ip[0] > buf->ip[1]) {
		swap(buf->ip[0], buf->ip[1]);
		swap(buf->port[0], buf->port[1]);
		swap_flag = 1;
	}

	hash = gp->hash_cb(buf);
	hash = hash % hd->bucket_num;
	buf->hash = hash;

	hash_table_lock(hd, hash, 0);
	session = hash_table_search(hd, hash, NULL, __session_compare, buf, NULL);

	if (session == NULL) {
		/*新建流*/
		session = (session_item_t *)malloc(sizeof(session_item_t));
		if (session == NULL) {
			log_error(syslog_p, "new session no space now\n");
			goto failed;
		}

		__init_session(session, buf, packet);
		INC_CNT(stats->session_count);
		session->index.hash = hash;
		status = hash_table_insert(hd, hash, session);
		if (status != 0) {
			log_error(syslog_p, "new session insert error, status=%d\n", status);
			goto failed;
		}
	} else if ((session->flag & SESSION_DIRTY) && (packet->top_packet == NULL)) {
        /*当前会话正在处理，把包存起来，等待下次处理*/
        packet_t *p = (packet_t *)session->packet;
        assert(p);
        while (p->next_packet != NULL) {
            p = p->next_packet;
        }
        p->next_packet = packet;
        packet->top_packet = session->packet;
        packet->flag |= PKT_DONT_FREE;
        hash_table_unlock(hd, hash, 0);
        return 0;
    }
	lp->session = session;

	if (swap_flag) {
		/*包的ip1和ip2已经交换过了，所以把包的方向换过来*/
		packet->dir = (session->dir ^ SESSION_DIR_MASK);
	} else {
		packet->dir = session->dir;
	}

    if (m_info == NULL) {
        int32_t v;

        tuple_info.dir = packet->dir;
        v = meta_buffer_item_add(packet->meta_hd, META_TYPE_TUPLE_INFO, &tuple_info, sizeof(tuple_info));
        if (v != 0) {
            log_error(syslog_p, "TUPLE_INFO add error!\n");
        }
    }
	__update_session_count(session, packet);
    session->packet = packet;
    if (session->app_type != INVALID_PROTO_ID && (session->app_state == gp->sf_conf->final_state)) {
        if (packet->flag & PKT_DONT_FREE) {
            /*这种情况的检查主要是由于前一个数据包已经查出协议特征，而当前的数据包到达这个地方的时候，
             * 有可能会话中还有未被处理的数据包，因此不能简单返回，还要检查一下*/
            __session_return_handle(lp, packet, session);
        } else {
            __clear_session(session);
            packet->pktag = next_stage_tag;
        }
    } else {
        session->flag |= SESSION_DIRTY;
        /*注意dirty位加的位置*/
	    packet->pktag = sf_plugin_tag;
        if (session->app_type == INVALID_PROTO_ID) {
            ff_item_t *ff;
            uint32_t ff_hash;

            ff_hash = ff_table_hash(gp->ff_table, session->index.ip[0], session->index.port[0]);
            ff_table_lock(gp->ff_table, ff_hash);
            ff = ff_table_search(gp->ff_table, ff_hash, session->index.ip[0], session->index.port[0]);
            if (ff == NULL) {
                ff_table_unlock(gp->ff_table, ff_hash);
                ff_hash = ff_table_hash(gp->ff_table, session->index.ip[1], session->index.port[1]);
                ff_table_lock(gp->ff_table, ff_hash);
                ff = ff_table_search(gp->ff_table, ff_hash, session->index.ip[1], session->index.port[1]);
            }
            if (ff == NULL) {
                ff_table_unlock(gp->ff_table, ff_hash);
            } else {
                /*这里不应该去访问父流，否则在删除时会有锁的问题，比较难解决*/
                /*set session variable and release ff_table lock*/
                session->app_type = ff->app_type;
                session->app_state = gp->sf_conf->final_state;
                ff_table_unlock(gp->ff_table, ff_hash);
                __session_return_handle(lp, packet, session);
            }
        }
    }
    hash_table_unlock(hd, hash, 0);
	return packet->pktag;
failed:
	INC_CNT(stats->session_failed);
	hash_table_unlock(hd, hash, 0);
	return 0;
}

static void* session_frm_result_get(module_info_t *this)
{
	info_local_t *info;

    info = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());
    assert(info);

    if (info->packet->pktag == session_buf_tag) {
        return info->packet;
    } else {
        info->proto_buf.packet = info->packet;
	    assert(info->session);
	    info->proto_buf.state = info->session->app_state;
	    info->proto_buf.protobuf_head = &info->session->protobuf_head;
        info->proto_buf.engine_id = info->session->engine_id;
        info->proto_buf.app_id = info->session->app_type;
	    return &info->proto_buf;
    }
    return NULL;
}

static void session_frm_result_free(module_info_t *this)
{
    info_local_t *info;

    info = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());
    assert(info);

	info->packet = NULL;
	info->session = NULL;
}


static int32_t session_frm_fini_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *lp = (info_local_t *)module_priv_rep_get(this, thread_id);
    info_global_t *gp = (info_global_t *)this->pub_rep;

    mutex_lock(&gp->lock);
    gp->stats.unknown_pkts += lp->stats.unknown_pkts;
    gp->stats.unknown_dir += lp->stats.unknown_dir;
    gp->stats.session_count += lp->stats.session_count;
    gp->stats.session_failed += lp->stats.session_failed;
    mutex_unlock(&gp->lock);

    free(lp);
    return 0;
}

static int32_t session_frm_fini_global(module_info_t *this)
{
    info_global_t *info = (info_global_t *)this->pub_rep;
    int rv;

    rv = event_base_loopbreak(info->timer.base);
    if (rv != 0) {
        log_error(syslog_p, "Event break error:%d\n", rv);
    }
    pthread_join(info->timer.tid, NULL);
    evtimer_del(&info->timer.ev);

    event_base_free(info->timer.base);

	__session_item_show(info, &info->stats);

	if (info != NULL) {
		if (info->log_c) {
			log_fini(&info->log_c);
		}
		if (info->session_table) {
			__session_table_clear(info->session_table, info->ff_table);
		}
	}

    ff_table_fini(info->ff_table);
	free(info);
	return 0;
}
