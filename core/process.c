#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "threadpool.h"
#include "sys.h"
#include "log.h"
#include "mem.h"
#include "conf.h"
#include "process.h"
#include "parser.h"

#define MAX_PACKET_HANDLE 2000

tag_hd_t *pktag_hd_p;
static zone_t *packet_zone;
extern module_hd_t *module_hd_p;
void worker_thread_process(void *data)
{
    packet_t *packet;
    packet_t *next;
    assert(data);

    packet = (packet_t *)data;

    packet->flag &= ~PKT_HANDLE_MASK;/*清理上次的结果*/
    module_list_process(module_hd_p, pktag_hd_p, packet->pktag, packet);
    if (packet->flag & PKT_LOOP_NEXT) {
       threadpool_add_task(tp, worker_thread_process, packet, 0);
    } else if (packet->flag & PKT_DONT_FREE) {
    } else {
        do {
            next = packet->next_packet;
            zone_free(packet_zone, packet);
            packet = next;
        } while (packet != NULL);
    }
}

void process_loop(module_hd_t *module_head)
{
	int32_t status, tag_id;
	extern int system_exit;
    module_info_t *recv;
    packet_t *packet;

    if (g_conf.mode == MODE_LIVE || g_conf.mode == MODE_FILE) {
    /*收包，线程中加入处理*/
        status = 0;
        packet_zone = zone_init("pcap_read", sizeof(packet_t) + MAX_PACKET_LEN, MAX_PACKET_HANDLE);
        assert(packet_zone);
        recv = module_info_get_from_name(module_head, "recv");
        assert(recv && recv->ops->process);
        do {
            do {
                packet = (void *)zone_alloc(packet_zone, 0);
            } while(packet == NULL);
            tag_id = recv->ops->process(recv, packet);
            if (tag_id > 0) {
                assert(packet->data);
                status = threadpool_add_task(tp, worker_thread_process, packet, 0);
                if (status != 0) {
                    log_error(syslog_p, "Threadpool add task, status %d\n", status);
                    status = 0;
                }
            } else {
                status = tag_id;
                zone_free(packet_zone, packet);
            }
        } while( status >= 0 && !system_exit);
        if (g_conf.mode == MODE_FILE) {
            sleep(1);/*等待最后加入的work处理完成*/
        }

    } else if (g_conf.mode == MODE_SE) {
        do {
            status = module_list_process(module_head, pktag_hd_p, -1, NULL);
	    } while (status >= 0 && !system_exit);
    }
}

void process_fini()
{
    if (g_conf.mode == MODE_LIVE || g_conf.mode == MODE_FILE) {
        zone_fini(packet_zone);
    }
}

