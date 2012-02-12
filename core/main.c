#include <stdio.h>
#include <assert.h>
#include <signal.h>

#include "common.h"
#include "threadpool.h"
#include "conf.h"
#include "sys.h"
#include "log.h"
#include "module_manage.h"
#include "modules.h"
#include "tag_manage.h"
#include "process.h"
#include "test.h"

#define MAX_MODULE_NUM  20
#define MAX_TAG_NUM  40

static void (*original_sig_int)(int num);
static void (*original_sig_term)(int num);

volatile int system_exit;
module_hd_t *module_hd_p;
log_t *syslog_p;
#ifdef __linux__
struct threadpool *tp;
#endif

void cap_term(int signum)
{
    system_exit = 1;
    if (original_sig_int)
        signal(SIGINT, original_sig_int);
    if(original_sig_term)
        signal(SIGTERM, original_sig_term);
}

static int32_t __sys_init()
{
    original_sig_int = signal(SIGINT, cap_term);
    original_sig_term = signal(SIGTERM, cap_term);

    system_exit = 0;

	/*日志*/
	if ((syslog_p = log_init(g_conf.logfile, DEBUG)) == NULL) {
		return -INIT_ERROR;
	}

   return STATUS_OK;
}

static int32_t __sys_fini()
{
    if (log_fini(&syslog_p) != 0) {
		return -FINI_ERROR;
	}
    return STATUS_OK;
}
static int32_t __thread_init()
{
    assert(sys_thread_init_global() == 0);

    tp = threadpool_init(g_conf.thread_num, sys_thread_init_local);
    assert(tp);
    return 0;
}

static int32_t __thread_fini()
{
    threadpool_free(tp, 1);//等待所有worker线程退出
    if (sys_thread_fini_global() != 0) {
        return -FINI_ERROR;
    }
    return 0;
}

static tag_hd_t* __tag_init()
{
	tag_hd_t *tag_hd;
	tag_hd = tag_init(MAX_TAG_NUM);
	tag_register(tag_hd, "start");
	tag_register(tag_hd, "decap");
	tag_register(tag_hd, "gtp");
	tag_register(tag_hd, "gre");
	tag_register(tag_hd, "l2tp");
	tag_register(tag_hd, "ipv4_frag");
	tag_register(tag_hd, "ipv6_frag");
	tag_register(tag_hd, "tcp"); /*8*/
	tag_register(tag_hd, "udp"); /*9*/
	tag_register(tag_hd, "sf_plugin");
	tag_register(tag_hd, "parsed");/*11*/
	tag_register(tag_hd, "session_buf");/*12*/
	assert(tag_hd);
	return tag_hd;
}

static void __tag_fini(tag_hd_t **tag_hd_pp)
{
	tag_fini(tag_hd_pp);
}

static module_hd_t* __module_init()
{
	module_hd_t *module_hd_p;
    uint32_t i;

	module_hd_p = module_list_create(MAX_MODULE_NUM);
	assert(module_hd_p);
	module_list_add(module_hd_p, "recv", &recv_mod_ops);
	module_list_add(module_hd_p, "decap", &decap_mod_ops);
	module_list_add(module_hd_p, "tunnel", NULL);
	module_list_add(module_hd_p, "reassemble", NULL);
	module_list_add(module_hd_p, "session", &session_frm_ops);
	module_list_add(module_hd_p, "sf_plugin", &sf_plugin_ops);
	module_list_add(module_hd_p, "action", NULL);

	module_tag_bind(module_hd_p, pktag_hd_p, "recv", "start");
	module_tag_bind(module_hd_p, pktag_hd_p, "decap", "decap");

	module_tag_bind(module_hd_p, pktag_hd_p, "tunnel", "gtp");
	module_tag_bind(module_hd_p, pktag_hd_p, "tunnel", "gre");
	module_tag_bind(module_hd_p, pktag_hd_p, "tunnel", "l2tp");

	module_tag_bind(module_hd_p, pktag_hd_p, "reassemble", "ipv4_frag");
	module_tag_bind(module_hd_p, pktag_hd_p, "reassemble", "ipv6_frag");

	module_tag_bind(module_hd_p, pktag_hd_p, "session", "tcp");
	module_tag_bind(module_hd_p, pktag_hd_p, "session", "udp");
    module_tag_bind(module_hd_p, pktag_hd_p, "session", "session_buf");
	module_tag_bind(module_hd_p, pktag_hd_p, "session", "parsed");

	module_tag_bind(module_hd_p, pktag_hd_p, "sf_plugin", "sf_plugin");

	assert(module_list_init_global(module_hd_p) == 0);

    for (i=0; i<g_conf.thread_num; i++) {
        assert(module_list_init_local(module_hd_p, i) == 0);
    }
	return module_hd_p;
}

static void __module_start(module_hd_t *module_hd_p)
{
	assert(module_list_start(module_hd_p) == 0);
}

static int32_t __module_fini(module_hd_t **module_hd_pp)
{
	int status;
    module_hd_t *module_hd_p = *module_hd_pp;
    uint32_t i;

    for (i=0; i<g_conf.thread_num; i++) {
        status = module_list_fini_local(module_hd_p, i);
        if_error_return(status == STATUS_OK, status);
    }
    module_list_fini_global(module_hd_p);
    status = module_manage_fini(module_hd_pp);
    if_error_return(status == STATUS_OK, status);

    return STATUS_OK;
}

int main(int argc, char *argv[])
{
	int32_t status;

/*获取配置*/
	conf_init();
	if (conf_read(argc, argv) != 0) {
		print("read conf error!\n");
	}

	test();

/*初始化*/
	assert(__sys_init() == 0);
	log_notice(syslog_p, "sys init OK!\n");

    assert(__thread_init() == 0);
    log_notice(syslog_p, "thread init OK!\n");

	pktag_hd_p  = __tag_init();
	assert(pktag_hd_p);
	log_notice(syslog_p, "tag init OK!\n");

	module_hd_p = __module_init();
	assert(module_hd_p);

    __module_start(module_hd_p);
	log_notice(syslog_p, "module init OK!\n");
/*开始处理*/
	process_loop(module_hd_p);
/*处理结束*/
    if (__thread_fini() == 0) {
        log_notice(syslog_p, "thread exit OK!\n");
    } else {
        log_notice(syslog_p, "thread exit error!\n");
    }
    process_fini();
	if (__module_fini(&module_hd_p) != 0) {
		log_error(syslog_p, "Some module finish error...\n");
	} else {
		log_notice(syslog_p, "module safe exit...\n");
	}

	__tag_fini(&pktag_hd_p);
	log_notice(syslog_p, "tag safe exit...\n");

   	conf_fini();

    if ((status = __sys_fini()) != 0) {
		print("sys fin status %d\n", status);
	} else {
		print("sys exit OK\n");
	}


	return 0;
}
