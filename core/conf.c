#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "conf.h"
#include "log.h"
#include "list.h"
#include "lua_ci.h"

conf_t g_conf;

#define DEFAULT_PROTOFILE_PATH "test/app.proto"
#define READ_BUF_SIZE 1024
#define PROTO_LIST_NAME "proto_list"
#define ENGINE_LIST_NAME "engine_list"
#define ENGINE_PDE_NAME "pde"
#define ENGINE_SDE_NAME "sde"

typedef struct conf_list {
	list_head_t list;
	char *name;
	void *data;
	conf_node_free_callback free_cb;
} conf_node_t;

static void __proto_conf_show(sf_proto_conf_t *conf);


static void __usage(char *prog_name)
{
	print("%s [-i ifname] [-r capfile] [-l logfile] [-n worker_thread_num] [-p protofile]\n", prog_name);
	exit (-1);
}

static void __init_default_config()
{
	g_conf.protofile = DEFAULT_PROTOFILE_PATH;
    g_conf.thread_num = 1;
}

static int __parse_args(int argc, char *argv[])
{
	int opt;
	while ((opt = getopt(argc, argv, "i:r:l:n:h")) > 0) {
		switch (opt) {
		case 'i':
			g_conf.mode = MODE_LIVE;
			g_conf.u.device = optarg;
			break;
		case 'r':
			g_conf.mode = MODE_FILE;
			g_conf.u.capfile = optarg;
			break;
		case 'l':
			g_conf.logfile = optarg;
			break;
		case 'p':
			g_conf.protofile = optarg;
			break;
        case 'n':
            g_conf.thread_num = atoi(optarg);
            break;
		case 'h':
		default:
			__usage(argv[0]);
			exit (-1);
			break;
		}
	}
	return 0;
}

uint32_t __read_file(char *filename, char **rd_buf, int init_size, int step)
{
	char buf[READ_BUF_SIZE];
	FILE *fp;
	int fd;
	char *p, *head;
	uint32_t total_size, count, read_size;

	assert(filename);
	if (init_size < READ_BUF_SIZE) {
		init_size = READ_BUF_SIZE;
	}

	fp = fopen(filename, "r");
	assert(fp);

	fd = fileno(fp);

	p = malloc(init_size);
    if (p == NULL) {
        print("malloc error !\n");
        return 0;
    }

	head = p;
	read_size = 0;
	total_size = init_size;
	while ((count = read(fd, buf, READ_BUF_SIZE)) != 0) {
        if ((p + count) > (head + total_size)) {
			if ((p+count) > (head + total_size) + step) {
				step = p + count - (head+total_size);
			}
			p = realloc(head, total_size + step);
            if (p != NULL) {
                head = p;
				total_size += step;
				p += read_size;
			} else {
                print("realloc failed");
				return 0;
			}
		}
		memcpy(p, buf, count);
        p += count;
		read_size += count;
	}
	fclose(fp);
	*rd_buf = head;
	return read_size;
}

void __common_data_create_add(const char *key, const char *value, common_data_head_t *data_head)
{
    list_head_t *head = &data_head->list;
    common_data_t *data;

    data = zmalloc(common_data_t *, sizeof(common_data_t));
    assert(data);

    if (key != NULL) {
        data->key = malloc(strlen(key));
        strcpy(data->key, key);
    }
    if (value != NULL) {
        data->value = malloc(strlen(value));
        strcpy(data->value, value);
    }
    list_add_tail(&data->list, head);
    data_head->item_num++;
}

void __common_data_show(common_data_head_t *head)
{
    list_head_t *list_head, *p;
    if (head->item_num <= 0) {
        return;
    }
    do {
        list_head = &head->list;
        printf("\t\t");
        list_for_each(p, list_head) {
            common_data_t *data = list_entry(p, common_data_t, list);
            if (data->key != NULL) {
                printf("key:%s, ", data->key);
            }
            if (data->value != NULL) {
                printf("value:%s ", data->value);
            }
        }
        printf("\n");
        head = head->next;
    } while(head != NULL);
}
void __common_data_free(common_data_head_t *head)
{
    list_head_t *list_head, *temp, *p;
    common_data_head_t *next;

    do {
        list_head = &head->list;
        list_for_each_safe(p, temp, list_head) {
            common_data_t *data = list_entry(p, common_data_t, list);
            if (data->key != NULL) {
                free(data->key);
            }
            if (data->value != NULL) {
                free(data->value);
            }
        }
        next = head->next;
        free(head);
        head = next;
    } while(head != NULL);
}

void __get_lua_table_config(lua_State *L, common_data_head_t *head)
{
    uint32_t table_num, index;
    uint32_t i;
    common_data_head_t **pp = NULL;
    const char *key, *value;

    table_num = lua_objlen(L, -1);

    for (i=1; i<=table_num; i++) {
        int flag = 1;
        lua_rawgeti(L, -1, i);
        index = lua_gettop(L);
        lua_pushnil(L);
        while (lua_next(L, index) != 0) {
            if (flag && (i != 1)) {
                head = zmalloc(common_data_head_t *, sizeof(common_data_head_t));
                LIST_HEAD_INIT(&head->list);
                assert(head);
                *pp = head;
                flag = 0;
            } else if (i == 1) {
                flag = 0;
            }
            assert(lua_type(L, -1) == LUA_TSTRING);
            assert(lua_type(L, -2) == LUA_TSTRING || lua_type(L, -2) == LUA_TNUMBER);

            value = lua_tostring(L, -1);
            if (lua_type(L, -2) != LUA_TSTRING) {
                key = NULL;/*need to be fixed*/
            } else {
                key = lua_tostring(L, -2);
            }
            printf("add key %s, value %s\n", key, value?value:"NULL");
            __common_data_create_add(key, value, head);
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        if (flag == 0) {
            pp = (void *)&head->next;
        }
    }
}

int32_t __engines_conf_read(lua_State *L, char *engine_name, common_data_head_t *conf)
{
    int type;

    if (!ldlua_has_table(L, engine_name)) {
        return 0;
    }
	type = ldlua_table_item_type(L, engine_name, "conf");
    if (type != LUA_TTABLE) {
        /*No configuation found */
        return 0;
    } else {
        ldlua_table_raw_get(L, engine_name);
        lua_getfield(L, -1, "conf");
        __get_lua_table_config(L, conf);
        lua_pop(L, 2); /*balance the stack*/
    }
    return 0;
}

int32_t __proto_item_read(lua_State *L, char *proto_name, int index, sf_proto_conf_t *conf)
{
	uint32_t i;
	int type;
	proto_conf_t *p;

	p = &conf->protos[index];

	assert(conf->engines);
	p->name = malloc(strlen(proto_name) + 1);
	assert(p->name);
	strcpy(p->name, proto_name);

	p->engine_head = zmalloc(common_data_head_t *, sizeof(common_data_head_t) * conf->total_engine_num);
	assert(p->engine_head);

	for (i=0; i<conf->total_engine_num; i++) {
		type = ldlua_table_item_type(L, proto_name, conf->engines[i].name);
        LIST_HEAD_INIT(&p->engine_head[i].list);
		if (type <= 0) {
			p->engine_head[i].lua_type = -1;
		} else {
			p->engine_head[i].lua_type = type;
			p->engine_mask |= 1<<i;
		}
		if (type == LUA_TSTRING) {
			char *str;
			str = ldlua_table_key_get_string(L, proto_name, conf->engines[i].name);
			assert(str && strlen(str) > 0);
            __common_data_create_add(NULL, str, &p->engine_head[i]);
		} else if (type == LUA_TTABLE) {
            ldlua_table_raw_get(L, proto_name);
            lua_getfield(L, -1, conf->engines[i].name);
            __get_lua_table_config(L, &p->engine_head[i]);
            lua_pop(L, 2); /*balance the stack*/
      }
	}
	return 0;
}

sf_proto_conf_t *__proto_conf_read()
{
	sf_proto_conf_t *sf_conf;
	uint32_t read_size;
	lua_State *L;
	int error;
	int proto_num, total_engine_num;
	int i;

	sf_conf = zmalloc(sf_proto_conf_t *, sizeof(sf_proto_conf_t));
	assert(sf_conf);

	read_size = __read_file(g_conf.protofile, &sf_conf->app_luabuf, READ_BUF_SIZE, READ_BUF_SIZE);
	if (read_size == 0) {
		free(sf_conf);
		return NULL;
	} else {
		print("read size %d\n", read_size);

		L = luaL_newstate();
		assert(L);
		luaL_openlibs(L);
		luaL_loadbuffer(L, sf_conf->app_luabuf, read_size, "app_parser");
        error = lua_pcall(L, 0, 0, 0);
		if (error) {
			err_print("%s\n", lua_tostring(L, -1));
			lua_pop(L, 1);
			free(sf_conf);
			return NULL;
		}
	}

	total_engine_num = ldlua_table_items_num(L, ENGINE_LIST_NAME);
	assert(total_engine_num);
	sf_conf->total_engine_num = total_engine_num;

	sf_conf->final_state = ldlua_table_key_get_num(L, "gstate", "final");
	assert(sf_conf->final_state);

	sf_conf->engines = zmalloc(detect_engine_t *, total_engine_num * sizeof(detect_engine_t));
	assert(sf_conf->engines);

	for (i=1; i<=total_engine_num; i++) {
		char *p;
		p = ldlua_table_raw_get_string(L, ENGINE_LIST_NAME, i);
		assert(strlen(p) <= ENGINE_NAME_LEN);
		strcpy(sf_conf->engines[i-1].name, p);
        sf_conf->engines[i-1].conf = zmalloc(common_data_head_t *, sizeof(common_data_t));
        assert(sf_conf->engines[i-1].conf);
        LIST_HEAD_INIT(&sf_conf->engines[i-1].conf->list);

        assert(__engines_conf_read(L, p, sf_conf->engines[i-1].conf) == 0);
	}

	proto_num = ldlua_table_items_num(L, PROTO_LIST_NAME);
	assert(proto_num);
	sf_conf->total_proto_num = proto_num;
	sf_conf->protos = zmalloc(proto_conf_t *, proto_num * sizeof(proto_conf_t));

	for (i=1; i<=proto_num; i++) {
		char *proto_name;
		proto_name = ldlua_table_raw_get_string(L, PROTO_LIST_NAME, i);
		if (proto_name) {
			__proto_item_read(L, proto_name, i-1, sf_conf);
		} else {
			err_print("item %d type error, %s\n",
					  i, lua_typename(L, lua_type(L, -1)));
		}
	}

	__proto_conf_show(sf_conf);

    assert(lua_gettop(L) == 0);
	lua_close(L);
	return sf_conf;
}

void __proto_conf_show(sf_proto_conf_t *conf)
{
	uint32_t i, j;

	print("total_engine_num=%d, list:\n", conf->total_engine_num);
	for (i=0; i<conf->total_engine_num; i++) {
		print("\t%s\n", conf->engines[i].name);
	}

	print("total_proto_num=%d\n", conf->total_proto_num);
	for (i=0; i<conf->total_proto_num; i++) {
		print("\tname:%s,engine_mask:%d\n", conf->protos[i].name, conf->protos[i].engine_mask);
		for (j=0; j<conf->total_engine_num; j++) {
			print("\t\tengine:%s, type:%d\n", conf->engines[j].name,
				  conf->protos[i].engine_head[j].lua_type);
            __common_data_show(&conf->protos[i].engine_head[j]);
		}
	}
}

void __proto_conf_free(void *data)
{
	sf_proto_conf_t *conf;
	uint32_t i;

	conf = (sf_proto_conf_t *)data;

	if (conf->app_luabuf) {
		free(conf->app_luabuf);
	}
	if (conf->engines) {
        for (i=0; i<conf->total_engine_num; i++) {
            __common_data_free(conf->engines[i].conf);
        }
        free(conf->engines);
	}

	if (conf->protos) {
		for (i=0; i<conf->total_proto_num; i++) {
			if (conf->protos[i].name) {
				free(conf->protos[i].name);
			}
			if (conf->protos[i].engine_head) {
                __common_data_free(conf->protos[i].engine_head);
			}
		}
		free(conf->protos);
	}

	free(conf);
}

int32_t conf_init()
{
	memset(&g_conf, 0, sizeof(conf_t));
	LIST_HEAD_INIT(&g_conf.module_conf_head);
	__init_default_config();
	return 0;
}

int32_t conf_read(int argc, char *argv[])
{
	/*读取命令行参数*/
	void *data;
	assert(__parse_args(argc, argv) == 0);

	if (g_conf.mode != MODE_LIVE && g_conf.mode != MODE_FILE) {
		__usage(argv[0]);
		exit (-1);
	}

	/*读取配置文件*/
	data = __proto_conf_read();
	assert(data);
	assert(conf_module_config_insert(SF_PROTO_CONF_NAME, data, __proto_conf_free) == 0);
	return 0;
}

static inline int32_t __conf_insert(list_head_t *head, char *name, void *data,
									conf_node_free_callback free_cb)
{
	conf_node_t *node;

	node = zmalloc(conf_node_t *, sizeof(conf_node_t));
	if_error_return(node != NULL, -NO_SPACE_ERROR);
	node->name = name;
	node->data = data;
	node->free_cb = free_cb;
	list_add_tail(&node->list, head);
	return 0;
}

static inline void* __conf_search(list_head_t *head, void *pos, char *name)
{
	list_head_t *p;
	int found = 0;

	list_for_each(p, head) {
		conf_node_t *node = list_entry(p, conf_node_t, list);
		if ((pos != NULL) && !found) {
			if (pos == node->data) {
                /*跳过这个节点，从下一个开始*/
                found = 1;
			}
			continue;
		}
		if (strcmp(node->name, name) == 0) {
			return node->data;
		}
	}
	return NULL;
}

int32_t conf_module_config_insert(char *name, void *config, conf_node_free_callback free_cb)
{
	return __conf_insert(&g_conf.module_conf_head, name, config, free_cb);
}

void* conf_module_config_search(char *name, void *pos)
{
	return __conf_search(&g_conf.module_conf_head, pos, name);
}

int32_t conf_fini()
{
	list_head_t *p, *tmp;
	list_for_each_safe(p, tmp, &g_conf.module_conf_head) {
		conf_node_t *node = list_entry(p, conf_node_t, list);
		if (node != NULL) {
			list_del(&node->list);
			if (node->free_cb) {
				node->free_cb(node->data);
			}
			free(node);
		}
	}
	return 0;
}
