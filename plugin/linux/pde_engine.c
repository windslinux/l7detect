#include <string.h>
#include <assert.h>

#include "common.h"
#include "decap.h"
#include "plugin.h"
#include "module_manage.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "helper.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "ldlua.h"
#include "engine_comm.h"

static int32_t pde_engine_init_global(module_info_t *this);
static int32_t pde_engine_process(module_info_t *this, void *data);
static int32_t pde_engine_fini_global(module_info_t *this);

static log_t *ptlog_p;

#define PDE_PROTO_NUM 2 /*TCP or UDP*/
#define PDE_PORT_NUM 65536

#define skip_space(p) do {						\
		if (*p == ' ') {							\
			p++;								\
		} else {								\
			break;								\
		}										\
	} while(p)

module_ops_t pde_engine_ops = {
	.init_global = pde_engine_init_global,
    .init_local = NULL,
	.start = NULL,
	.process = pde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = pde_engine_fini_global,
	.fini_local = NULL,
};

typedef struct info_global {
	sf_proto_conf_t *conf;
	uint32_t pde_engine_id;
	longmask_t* pde_table[PDE_PROTO_NUM][PDE_PORT_NUM];
	//list_head_t *pde_table[PDE_PROTO_NUM];
} info_global_t;

kv_table_t pde_prot[] = {
	{"tcp", DPI_IPPROT_TCP},
	{"udp", DPI_IPPROT_UDP},
	{NULL, 0},
};

static int32_t __parse_pde_proto_conf(proto_conf_t *proto_conf,
									  uint32_t app_id, uint32_t engine_id,
									  longmask_t* pde_table[PDE_PROTO_NUM][PDE_PORT_NUM])
{
	char *pde_str, *p, *q;
	uint16_t proto, port;
	int32_t i;
	common_data_head_t *engine_head;
    common_data_t *engine_data;

	engine_head = &proto_conf->engine_head[engine_id];
	assert(engine_head);

	if (engine_head->lua_type != LUA_TSTRING) {
		log_error(ptlog_p, "pde data type error:%d\n", engine_head->lua_type);
		return -INVALID_PARAM;
	} else {
        assert(engine_head->item_num == 1);
        engine_data = list_entry(engine_head->list.next, common_data_t, list);
		pde_str = engine_data->value;
		p = pde_str;
		do {
			q = strtok(p, ",");
			p = NULL;
			if (q != NULL) {
				skip_space(q);
				i = kv_get_index_from_key(pde_prot, q);
				if (i < 0 || i >= PDE_PROTO_NUM) {
					log_error(ptlog_p, "pde format error, protocol not found:%s\n", q);
					return -INVALID_PARAM;
				} else {
					q += strlen(pde_prot[i].key);
					proto = i;
					skip_space(q);
					if (*q++ != '/') {
						log_error(ptlog_p, "pde format error, slice not found:%s\n", q);
						return -INVALID_PARAM;
					}
					port = strtoull(q, NULL, 0);
					if (port == 0) {
						log_error(ptlog_p, "pde format error, port not found:%s\n", q);
						return -INVALID_PARAM;
					}
					longmask_bit_set(pde_table[proto][port], app_id);
				}
			}
		} while(q != NULL);
	}
	return 0;
}

static int32_t __pde_conf_read(sf_proto_conf_t *conf, uint32_t pde_engine_id,
							   longmask_t* pde_table[PDE_PROTO_NUM][PDE_PORT_NUM])
{
	uint32_t i;
	proto_conf_t *protos = conf->protos;
	//int32_t proto_id;

	assert(protos);

	for (i=0; i<conf->total_proto_num; i++) {
		if ((conf->protos[i].engine_mask & (1<<pde_engine_id)) == 0) {
			continue;
		}
		if (__parse_pde_proto_conf(&conf->protos[i], i, pde_engine_id,
								   pde_table) != 0) {
			log_error(ptlog_p, "parse protocol [%s] error, system halt\n", conf->protos[i].name);
			exit(-1);
		}
	}
	return 0;
}

static int32_t pde_engine_init_global(module_info_t *this)
{
	sf_proto_conf_t *conf = (sf_proto_conf_t *)this->pub_rep;
	info_global_t *info;
	int32_t status;
	uint32_t i, j;

	info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	info->conf = conf;
	ptlog_p = conf->proto_log;

	for (i=0; i<PDE_PROTO_NUM; i++) {
		longmask_t *p;
		for (j=0; j<PDE_PORT_NUM; j++) {
			p = longmask_create(conf->total_proto_num);
			assert(p);
			info->pde_table[i][j] = p;
		}
	}

	info->pde_engine_id = engine_id_get(conf, "pde");
	assert(info->pde_engine_id != INVALID_ENGINE_ID);

   	status = __pde_conf_read(conf, info->pde_engine_id, info->pde_table);
	assert(status == 0);

	this->pub_rep = (info_global_t *)info;
	return 0;
}

static int32_t pde_engine_process(module_info_t *this, void *data)
{
	proto_comm_t *proto_comm;
	packet_t *packet;
	dpi_ipv4_hdr_t *iphdr;
	dpi_l4_hdr_t *l4hdr;
	int proto_index;
	info_global_t *info;
	uint16_t port;
	sf_proto_conf_t *conf;
	uint32_t tag = 0;
	int32_t app_id;

	info = (info_global_t *)this->pub_rep;
	conf = info->conf;
	proto_comm = (proto_comm_t *)data;
	packet = proto_comm->packet;

	iphdr = (dpi_ipv4_hdr_t *)((void *)packet->data + packet->prot_offsets[packet->prot_depth-2]);
	l4hdr = (dpi_l4_hdr_t *)((void *)packet->data + packet->prot_offsets[packet->prot_depth-1]);
	proto_index = kv_get_index_from_value(pde_prot, iphdr->protocol);
	if ((proto_index == -1) || (proto_index >= PDE_PROTO_NUM)) {
		return info->pde_engine_id + 1;
	}

	if ((packet->dir & PKT_DIR_MASK) == PKT_DIR_UPSTREAM) {
		port = ntohs(l4hdr->dst_port);
	} else {
		port = ntohs(l4hdr->src_port);
	}

    proto_comm->engine_id = info->pde_engine_id;
	/*处理上一个引擎发过来的mask*/
	longmask_op_and(proto_comm->match_mask[info->pde_engine_id], info->pde_table[proto_index][port]);
	app_id = handle_engine_mask(conf, proto_comm->match_mask[info->pde_engine_id],
                                CS_ENG_TYPE, proto_comm->match_mask,
                                info->pde_engine_id, &tag, 1);
	longmask_all_clr(proto_comm->match_mask[info->pde_engine_id]);

	if (app_id < 0) {
		/*处理本引擎开始的mask*/
		app_id = handle_engine_mask(conf, info->pde_table[proto_index][port],
                                    CS_ENG_TYPE, proto_comm->match_mask,
									info->pde_engine_id, &tag, 0);
	}
	if (app_id >= 0) {
		proto_comm->app_id = app_id;
	    proto_comm->state = conf->final_state;
	} else {
		proto_comm->app_id = INVALID_PROTO_ID;
	    proto_comm->state = 0;
	}
	return tag;
}

static int32_t pde_engine_fini_global(module_info_t *this)
{
	info_global_t *info;
	uint32_t i, j;

	info = (info_global_t *)this->pub_rep;
	for (i=0; i<PDE_PROTO_NUM; i++) {
		for (j=0; j<PDE_PORT_NUM; j++) {
			if (info->pde_table[i][j] != NULL) {
				longmask_destroy(info->pde_table[i][j]);
			}
		}
	}

	if (info) {
		free(info);
	}
	return 0;
}

