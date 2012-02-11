#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <assert.h>

#include "common.h"
#include "module_manage.h"
#include "log.h"
#include "helper.h"

module_hd_t *module_list_create(int max_module_num)
{
	module_hd_t *head_p;

	assert(max_module_num);
	head_p = zmalloc(module_hd_t *, sizeof(module_hd_t));
	assert(head_p);

	head_p->module_max = max_module_num + 1;
	head_p->module_valid = 0;
	head_p->module_info = zmalloc(module_info_t *, sizeof(module_info_t) * (max_module_num+1));
	assert(head_p->module_info);
	return head_p;
}

int32_t module_list_add(module_hd_t *head_p, char *name, module_ops_t *ops)
{
	int i = 0;
	module_info_t *modules;

	assert(head_p);
	assert(head_p->module_info);
	assert(name);
	assert(head_p->module_valid + 1 < head_p->module_max);

	modules= head_p->module_info;
	i = head_p->module_valid + 1;
	modules[i].name = name;
	modules[i].ops = ops;
	head_p->module_valid++;
	return STATUS_OK;
}

void module_tag_bind(module_hd_t *module_head, tag_hd_t *tag_head, char *module_name, char *tag_name)
{
	int tag_index, module_index;
	tag_info_t *tag_info;

	module_index = module_id_get_from_name(module_head, module_name);
	assert(module_index);

	tag_index = tag_id_get_from_name(tag_head, tag_name);
	assert(tag_index);

	tag_info = tag_head->tag_info;
	tag_info[tag_index].module_id = module_index;
}

int32_t module_list_init_global(module_hd_t *head_p)
{
	int i;
	int status;
	module_info_t *modules;

	assert(head_p);
	assert(head_p->module_info);
	modules	= head_p->module_info;

	for (i=1; i<(int)head_p->module_valid + 1; i++) {
		if ((modules[i].ops != NULL) && (modules[i].ops->init_global != NULL)) {
			status = modules[i].ops->init_global(&modules[i]);
			assert(status == 0);
		}
	}
	return STATUS_OK;
}

int32_t module_list_init_local(module_hd_t *head_p, uint32_t thread_id)
{
	int i;
	int status;
	module_info_t *modules;

	assert(head_p);
	assert(head_p->module_info);
	modules	= head_p->module_info;

	for (i=1; i<(int)head_p->module_valid + 1; i++) {
		if ((modules[i].ops != NULL) && (modules[i].ops->init_local != NULL)) {
			status = modules[i].ops->init_local(&modules[i], thread_id);
			assert(status == 0);
		}
	}
	return STATUS_OK;
}

void* module_priv_rep_get(module_info_t *module, uint32_t thread_id)
{
    assert(thread_id < MAX_WORKER_THREAD);
    return module->priv_rep[thread_id];
}

void module_priv_rep_set(module_info_t *module, uint32_t thread_id, void *data)
{
    assert(thread_id < MAX_WORKER_THREAD);
    module->priv_rep[thread_id] = data;
}

int32_t module_list_start(module_hd_t *head_p)
{
	int i;
	int status;
	module_info_t *modules;

	assert(head_p);
	assert(head_p->module_info);

	modules = head_p->module_info;

	for (i=1; i<(int)head_p->module_valid + 1; i++) {
		if ((modules[i].ops != NULL) && (modules[i].ops->start != NULL)) {
			status = modules[i].ops->start(&modules[i]);
			assert(status == 0);
		}
	}
	return STATUS_OK;
}

int32_t module_list_process(module_hd_t *head_p, tag_hd_t *tag_p, int32_t init_tag, void *init_data)
{
	int32_t last, current, tagid;
	module_info_t *modules, *current_mod, *last_mod;
	module_ops_t *current_ops, *last_ops;
	void *data;
	uint16_t i;
	uint64_t module_hit_mask = 0;

	assert(head_p);
	assert(head_p->module_info);

	modules = head_p->module_info;

	last = 0;
	if (init_tag <= 0) {
		current = tagid = 1;
	} else if (tag_p != NULL) {
		tagid = init_tag;
		current = module_id_get_from_tag_id(tag_p, tagid);
	} else {
		tagid = init_tag;
		current = init_tag;
	}
	if (!init_data) {
		data = NULL;
	} else {
		data = init_data;
	}

	do {
		current_mod = &modules[current];
		current_ops = current_mod->ops;
		last_mod = &modules[last];
		last_ops = last_mod->ops;

		if ((current_ops != NULL) && (current_ops->process != NULL)) {
			if (last_ops && last_ops->result_get != NULL) {
				data = last_ops->result_get(last_mod);
			}

			tagid = current_ops->process(&modules[current], data);
			module_hit_mask |= 1<<current;
			if (tagid < 0) {
				return tagid;
			}
			last = current;
			if (tag_p != NULL) {
				current = module_id_get_from_tag_id(tag_p, tagid);
			} else {
				current++;
			}
		} else {
			break;
		}
	} while ((current > 0) && ((uint32_t)current <= head_p->module_valid));

	for (i=1; i<= head_p->module_valid; i++) {
		if (module_hit_mask & (1<<i)) {
			if (modules[i].ops != NULL && modules[i].ops->result_free) {
				modules[i].ops->result_free(&modules[i]);
			}
		}
	}

	return STATUS_OK;
}

module_info_t *module_info_get_from_name(module_hd_t *head_p, char *name)
{
	uint16_t i;
	module_info_t *modules;

	assert(head_p);
	assert(head_p->module_info);
	modules = head_p->module_info;

	for (i=1; i<=head_p->module_valid; i++) {
		if (strcmp(modules[i].name, name) == 0) {
			break;
		}
	}
	if (i <= head_p->module_valid) {
		return &modules[i];
	}
	return NULL;
}

uint16_t module_id_get_from_name(module_hd_t *head_p, char *name)
{
	uint16_t i;
	module_info_t *modules;

	assert(head_p);
	assert(head_p->module_info);
	modules =  head_p->module_info;

	for (i=1; i<=head_p->module_valid; i++) {
		if (strcmp(modules[i].name, name) == 0) {
			break;
		}
	}
	if (i <= head_p->module_valid) {
		return i;
	} else {
		return 0;
	}
}

void module_list_show(module_hd_t *head_p)
{
	int i;
	module_info_t *modules;

	if(head_p == NULL) {
		return;
	}

    modules =  head_p->module_info;

	print("ewx module information:\n");
	print("%16s %5s\n", "module name", "id");

	if (modules != NULL) {
		for (i=1; i<(int)head_p->module_valid + 1; i++) {
			print("%16s %5d\n", modules[i].name, i);
		}
	}
}

int32_t module_list_fini_global(module_hd_t *head_p)
{
	int i, valid;
	int status;
	module_info_t *modules;

	if (head_p != NULL) {
		modules = head_p->module_info;
		if (modules != NULL) {
			valid = head_p->module_valid;
			for (i=(int)valid; i>=1; i--) {
				if ((modules[i].ops != NULL) && (modules[i].ops->fini_global != NULL)) {
					log_notice(syslog_p, "fini module %s\n", modules[i].name);
					modules[i].flags |= MODULE_QUIT;
					status = modules[i].ops->fini_global(&modules[i]);
					if (status != 0) {
						log_notice(syslog_p, "module %s fini status %d\n",
                                    modules[i].name, status);
					}
				}
			}
		}
	}
	return STATUS_OK;
}

int32_t module_list_fini_local(module_hd_t *head_p, uint32_t thread_id)
{
	int i, valid;
	int status;
	module_info_t *modules;

	if (head_p != NULL) {
		modules = head_p->module_info;
		if (modules != NULL) {
			valid = head_p->module_valid;
			for (i=(int)valid; i>=1; i--) {
			log_notice(syslog_p, "fini module local %s on thread %d\n", modules[i].name, thread_id);
				if ((modules[i].ops != NULL) && (modules[i].ops->fini_local != NULL)) {
					modules[i].flags |= MODULE_QUIT;
					status = modules[i].ops->fini_local(&modules[i], thread_id);
					if (status != 0) {
						log_notice(syslog_p, "module %s fini status %d on thread %d\n",
                                    modules[i].name, status, thread_id);
					}
				}
			}
		}
	}
	return STATUS_OK;
}


int32_t module_manage_fini(module_hd_t **head_pp)
{
	module_info_t *modules;
	module_hd_t *head_p = *head_pp;

    if (head_p != NULL) {
		modules = head_p->module_info;
		if (modules != NULL) {
			free(modules);
		}
		free(head_p);
		*head_pp = NULL;
	}
	return STATUS_OK;
}
