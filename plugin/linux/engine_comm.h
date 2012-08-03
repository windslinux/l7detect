#ifndef __ENGINE_COMM_H__
#define __ENGINE_COMM_H__

#include "common.h"
#include "list.h"
#include "parser.h"
#include "longmask.h"
#include "conf.h"

uint32_t engine_id_get(sf_proto_conf_t *conf, char *engine_name);
uint32_t app_id_get(sf_proto_conf_t *conf, char *app_name);

static inline uint32_t get_tag_from_engine_id(sf_proto_conf_t *conf, uint32_t engine_id, uint32_t engine_type, uint32_t total_engine_num)
{
	uint32_t tag = engine_id + 1;

    assert(engine_type <= MAX_ENGINE_TYPE);
	if (tag <= total_engine_num) {
        if ((1 << engine_id) & conf->engine_type_mask[engine_type]) {
    		return tag;
        }
    }
    return 0;
}

static inline uint32_t this_engine_mask(sf_proto_conf_t *conf, uint32_t engine_mask, uint32_t engine_type)
{
    if (engine_type > MAX_ENGINE_TYPE) {
        return 0;
    } else {
        return (engine_mask & conf->engine_type_mask[engine_type]);
    }
}

/*这种适合向端口或者IP一类的规则，一次可以获取所有的匹配结果*/
static inline int32_t handle_engine_mask(sf_proto_conf_t *conf, longmask_t *this_mask,
                                         int32_t engine_type,
										 longmask_t *match_mask[], uint32_t this_engine,
										 uint32_t *next_engine_tag,
										 uint32_t last_stage)
{
	int32_t bit = -1;
	uint16_t next_engine;
	int32_t flag = 0;

	do {
		bit = longmask_bit1_find(this_mask, bit + 1);
		if (bit >= 0) {
			uint32_t engine_mask, i;
			engine_mask = this_engine_mask(conf, conf->protos[bit].engine_mask, engine_type);
			i = this_engine + 1;

			if (!last_stage) {
				/*当处理的是从这个引擎开始的mask时，必须过滤掉mask不是从这个引擎开始的app*/
				if ((engine_mask & ~((0xffffffff) << this_engine)) != 0) {
					continue;
				}
			}

			/*没有其他引擎需要匹配，那么已经匹配到协议了，直接返回*/
			if ((engine_mask >> i) == 0) {
                uint32_t next_type_engine_mask;
                engine_type++;
                next_type_engine_mask = this_engine_mask(conf, conf->protos[bit].engine_mask, engine_type);
                if (next_type_engine_mask != 0) {
                    while ((next_type_engine_mask & (1<< i)) == 0) {
                        i++;
                    }
                    assert(i < conf->total_engine_num);
                    *next_engine_tag = get_tag_from_engine_id(conf, i, engine_type, conf->total_engine_num);
                    longmask_bit_set(match_mask[i], bit);
                } else {
                    *next_engine_tag = 0;
                }
				return bit;
			} else {
				while ((engine_mask & (1<<i)) == 0) {
					i++;
				}
				next_engine = i;
				if (!flag || (next_engine < *next_engine_tag)) {
					flag = 1;
					*next_engine_tag = get_tag_from_engine_id(conf, next_engine, engine_type, conf->total_engine_num);
				}
				longmask_bit_set(match_mask[next_engine], bit);
			}
		}
	} while(bit >= 0);

	if (*next_engine_tag == 0) {
		*next_engine_tag = get_tag_from_engine_id(conf, this_engine + 1, engine_type, conf->total_engine_num);
	}

   	return -1;
}

static inline int32_t handle_engine_appid(sf_proto_conf_t *conf,
										  longmask_t *this_mask,
                                          int32_t engine_type,
										  int32_t (*match)(void *data, uint32_t app_id),
										  void *data,
										  longmask_t *match_mask[], uint32_t this_engine,
										  uint32_t *next_engine_tag, uint32_t pre_stage,
										  int32_t *state)
{
	uint16_t next_engine;
	int32_t bit, flag = 0;
	int32_t result;

	bit = -1;
	do {
		bit = longmask_bit1_find(this_mask, bit + 1);
		if (bit >= 0) {
			uint32_t engine_mask, i;
			engine_mask = this_engine_mask(conf, conf->protos[bit].engine_mask, engine_type);

			i = this_engine + 1;

			if (!pre_stage) {
				/*当处理的是从这个引擎开始的mask时，必须过滤掉mask不是从这个引擎开始的app*/
				if ((engine_mask & ~((0xffffffff) << this_engine)) != 0) {
					continue;
				}
			}
			if ((result = match(data, bit)) <= 0) {
				continue;
			}
			*state = result;
			if (result != (int)conf->final_state) {
				/*中间状态，立即返回*/
				return bit;
			}
			/*没有其他引擎需要匹配，那么已经匹配到协议了，直接返回*/
			if ((engine_mask >> i) == 0) {
                uint32_t next_type_engine_mask;
                engine_type++;
                next_type_engine_mask = this_engine_mask(conf, conf->protos[bit].engine_mask, engine_type);
                if (next_type_engine_mask != 0) {
                    while ((next_type_engine_mask & (1<< i)) == 0) {
                        i++;
                    }

                    assert(i < conf->total_engine_num);
                    *next_engine_tag = get_tag_from_engine_id(conf, i, engine_type, conf->total_engine_num);
				    longmask_bit_set(match_mask[i], bit);
                } else {
                    *next_engine_tag = 0;
                }
				return bit;
			} else {
				while ((engine_mask & (1<<i)) == 0) {
					i++;
				}
				next_engine = i;
				if (!flag || (next_engine < *next_engine_tag)) {
					flag = 1;
					*next_engine_tag = get_tag_from_engine_id(conf, next_engine, engine_type, conf->total_engine_num);
				}

				longmask_bit_set(match_mask[next_engine], bit);
			}
		}
	} while(bit >= 0);

	if (*next_engine_tag == 0) {
		*next_engine_tag = get_tag_from_engine_id(conf, this_engine+1, engine_type, conf->total_engine_num);
	}
	return -1;
}
#endif
