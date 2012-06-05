#ifndef __META_BUF_H__
#define __META_BUF_H__

#define MAX_META_BUFFER_SIZE 2048
#define MAX_META_SIZE 256

enum {
	META_TYPE_FF_FLOW_IP,
	META_TYPE_FF_FLOW_PORT,
};

typedef struct meta_info {
	uint8_t type; /*最多有64中类型的元数据*/
	uint8_t length;/*元数据长度，这里不做太长的扩展，如果需要存储的元数据较大，应采用存放指针的方式*/
	union {
		uint16_t offset;
		uint16_t data;
	} u;
} meta_info_t;

typedef struct meta_head{
    uint16_t total_buf_size;
	uint16_t total_data_size;
	uint16_t current_data_size;
	uint8_t total_head_num;
	uint8_t current_head_num;
	void *data_start;
	meta_info_t head_info[0];
} meta_hd_t;

//@{
/** @defgroup meta_buf meta buffer的操作函数 */
/**
 * 初始化meta buffer
 *
 * @param meta_max_count 元数据最大的个数
 *
 * @return 设置好属性的meta buffer头指针
 */
meta_hd_t *meta_buffer_sys_create(uint16_t meta_max_count);

/**
 * 分配一个新的meta节点
 *
 * @param head meta buffer头指针
 * @param type meta类型
 * @param length data长度
 *
 * @return 成功，返回meta节点指针；否则，返回NULL
 */
meta_info_t *meta_buffer_alloc(meta_hd_t *head, uint16_t type, uint16_t length);

/**
 * meta节点设置函数，负责把元数据写入到元数据buffer中
 *
 * @param head meta buffer头指针
 * @param info meta节点指针
 * @param data 元数据
 *
 * @return 成功，返回0；否则，返回失败原因
 */
int32_t meta_buffer_item_set(meta_hd_t *head, meta_info_t *info, void *data);

/**
 * 获取一个meta节点，如果用户要修改meta节点，必须保证内存操作不会越界
 *
 * @param head meta buffer头指针
 * @param pos 搜索开始的位置，为NULL就从头开始，这个可用于搜索多次同一类型的数据
 * @param type meta节点类型
 *
 * @return 返回的节点指针
 */
meta_info_t *meta_buffer_item_get(meta_hd_t *head, void *pos, uint16_t type);

int32_t meta_buffer_item_add(meta_hd_t *head, uint16_t type,
								 void *data, uint16_t length);
/**
 * 获取meta节点的数据
 *
 * @param head meta buffer头指针
 * @param info meta节点信息
 *
 * @return meta节点的数据
 */
void *meta_buffer_item_get_data(meta_hd_t *head, meta_info_t *info);

int32_t meta_buffer_sys_clear(meta_hd_t*);
/**
 * meta buffer显示函数
 *
 * @param head meta buffer头指针
 */
void meta_buffer_show(meta_hd_t *head);

void meta_buffer_test();

void meta_buffer_sys_destroy(meta_hd_t *head);
//@}


#endif
