#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef __linux__
#include <dlfcn.h>
#endif

#include "common.h"
#include "log.h"
#include "sys.h"
#include "conf.h"
#include "module_manage.h"
#include "sf_plugin.h"
#include "plugin.h"
#include "process.h"

static int32_t sf_plugin_init_global(module_info_t *this);
static int32_t sf_plugin_init_local(module_info_t *this, uint32_t thread_id);
static int32_t sf_plugin_process(module_info_t *this, void *data);
static int32_t sf_plugin_fini_global(module_info_t *this);
static int32_t sf_plugin_fini_local(module_info_t *this, uint32_t thread_id);
static void *sf_plugin_result_get(module_info_t *this);

static uint16_t parsed_tag;
#define MAX_STRING_LEN 80

module_ops_t sf_plugin_ops = {
	.init_global = sf_plugin_init_global,
	.init_local = sf_plugin_init_local,
    .process = sf_plugin_process,
	.result_get = sf_plugin_result_get,
	.fini_global = sf_plugin_fini_global,
    .fini_local = sf_plugin_fini_local,
};

typedef struct info_global {
	uint32_t plugin_num;
	void **handle;
	module_hd_t *plugin;
	tag_hd_t *tag;
	sf_proto_conf_t *pconf;
} info_global_t;

typedef struct info_local {
    sf_proto_conf_t *pconf;
	proto_comm_t proto_comm;
} info_local_t;

static int32_t sf_plugin_init_global(module_info_t *this)
{
	module_ops_t *ops;
	info_global_t *info;
	char filename[MAX_STRING_LEN];
	char opsname[MAX_STRING_LEN];
	uint32_t i;
	module_info_t *plugin_info;
	int32_t status;
	sf_proto_conf_t *pconf;

	info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	pconf = conf_module_config_search(SF_PROTO_CONF_NAME, NULL);
	assert(pconf);

	info->plugin_num = pconf->total_engine_num;
	info->pconf = pconf;

	if (info->plugin_num == 0) {
		return 0;
	}
	info->plugin = module_list_create(info->plugin_num);
	assert(info->plugin);

	info->tag = tag_init(info->plugin_num);
	assert(info->tag);
	log_debug(syslog_p, "plugin number %d\n", info->plugin_num);

	info->handle = zmalloc(void **, sizeof(void *) * info->plugin_num);
	if_error_return(info->handle != NULL, -NO_SPACE_ERROR);
	i = 0;

	for (i=0; i<pconf->total_engine_num; i++) {
		sprintf(filename, ".libs/%s_engine.so", pconf->engines[i].name);
		log_notice(syslog_p, "open plugin %s\n", filename);
		info->handle[i] = dlopen(filename, RTLD_LAZY);
		log_notice(syslog_p, "plugin handle %p\n", info->handle[i]);
		if (!info->handle[i]) {
			log_notice(syslog_p, "%s\n", dlerror());
		}
		assert(info->handle[i]);

		sprintf(opsname, "%s_engine_ops", pconf->engines[i].name);

		ops = (module_ops_t *)dlsym(info->handle[i], opsname);

		if (dlerror() != NULL)  {
			log_error(syslog_p, "%s\n", dlerror());
			exit(-1);
		}
		assert(ops);
		status = module_list_add(info->plugin, pconf->engines[i].name, ops);
		assert(status == 0);

		tag_register(info->tag, pconf->engines[i].name);
		module_tag_bind(info->plugin, info->tag, pconf->engines[i].name, pconf->engines[i].name);

/*fixme:查到对应的plugin，通过设置resource来传入配置*/
		plugin_info = module_info_get_from_name(info->plugin, pconf->engines[i].name);
		assert(plugin_info);
		pconf->proto_log = syslog_p;
        plugin_info->pub_rep = (void *)pconf;
	}
	this->pub_rep = info;
	parsed_tag = tag_id_get_from_name(pktag_hd_p, "parsed");
	module_list_init_global(info->plugin);

	return 0;
}

static int32_t sf_plugin_init_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *info;
    info_global_t *gp;
    proto_comm_t *proto_comm;
    sf_proto_conf_t *pconf;
    uint32_t i;

    info = zmalloc(info_local_t *, sizeof(info_local_t));
	assert(info);

    gp = this->pub_rep;
    pconf = gp->pconf;
	proto_comm = &info->proto_comm;
	proto_comm->match_mask = zmalloc(longmask_t **, sizeof(longmask_t *) * pconf->total_engine_num);
	assert(proto_comm->match_mask);

	for (i=0; i<pconf->total_engine_num; i++) {
		proto_comm->match_mask[i] = longmask_create(pconf->total_proto_num);
		assert(proto_comm->match_mask[i]);
	}

    module_priv_rep_set(this, thread_id, (void *)info);

    gp = this->pub_rep;
    info->pconf = gp->pconf;
    module_list_init_local(gp->plugin, thread_id);
    return 0;
}

static int32_t sf_plugin_process(module_info_t *this, void *data)
{
    info_global_t *gp;
	info_local_t *lp;
	proto_comm_t *session_comm, *proto_comm;
	sf_proto_conf_t *pconf;
	uint32_t i;
	packet_t *packet;
	int32_t init_tag = 0;

    gp = this->pub_rep;
    lp = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());
	session_comm = (proto_comm_t *)data;
	packet = (packet_t *)session_comm->packet;
	pconf = gp->pconf;
	proto_comm = &lp->proto_comm;

    proto_comm->packet = packet;
	proto_comm->app_id = INVALID_PROTO_ID;
    proto_comm->thread_id = sys_thread_id_get();
	proto_comm->state = session_comm->state;
	proto_comm->protobuf_head = session_comm->protobuf_head;
	if (!list_empty(session_comm->protobuf_head)) {
		list_head_t *p, *head;

		head = session_comm->protobuf_head;
		list_for_each(p, head) {
			protobuf_node_t *node = list_entry(p, protobuf_node_t, list);
			assert(node->match_mask);
			longmask_copy(proto_comm->match_mask[node->engine_id], node->match_mask);
			if (!init_tag) {
				init_tag = node->engine_id + 1;
			}
		}

	} else {
		for (i=0; i<pconf->total_engine_num; i++) {
			longmask_all_clr(proto_comm->match_mask[i]);
		}
		init_tag = -1;
	}
	if (gp->plugin_num) {
		module_list_process(gp->plugin, gp->tag, init_tag, proto_comm);
	}

	if (proto_comm->app_id != INVALID_PROTO_ID) {
		packet->app_type = proto_comm->app_id;
	}
	packet->pktag = parsed_tag;
/*sf_plugin必须要再次回到会话模块，不能直接退出，否则将会导致有的会话一直处于dirty状态，导致死循环*/
	return packet->pktag;
}

static void *sf_plugin_result_get(module_info_t *this)
{
	info_local_t *info;

    info = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());
	return &info->proto_comm;
}

static int32_t sf_plugin_fini_local(module_info_t *this, uint32_t thread_id)
{
    uint32_t i;
    info_local_t *info;
    info_global_t *gp;
    sf_proto_conf_t *pconf;

    info = (info_local_t *)module_priv_rep_get(this, thread_id);
    gp = (info_global_t *)this->pub_rep;
    /*fini_local发生在fini_global之前，因此不能再使用global的变量*/
    pconf = info->pconf;

    for (i=0; i<pconf->total_engine_num; i++) {
		longmask_destroy(info->proto_comm.match_mask[i]);
	}
	free(info->proto_comm.match_mask);

    return module_list_fini_local(gp->plugin, thread_id);
}

static int32_t sf_plugin_fini_global(module_info_t *this)
{
	uint32_t i;
	info_global_t *info;

	info = (info_global_t *)this->pub_rep;

    module_list_fini_global(info->plugin);

	module_manage_fini(&info->plugin);
	tag_fini(&info->tag);

	for (i=0; i<info->plugin_num; i++) {
		if (info->handle[i] != NULL) {
			log_notice(syslog_p, "plugin %p close\n", info->handle[i]);
			dlclose(info->handle[i]);
		}
	}
	free(info->handle);
    free(info);
	return 0;
}

