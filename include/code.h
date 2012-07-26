#ifndef __CODE_H__
#define __CODE_H__

enum sys_code {
	STATUS_OK = 0,
	INIT_ERROR,
	NOT_INIT_READY,
    NOT_CLEAR_ERROR,
	INVALID_PARAM,
	NO_SPACE_ERROR,
	FINI_ERROR,
	ITEM_NOT_FOUND,
    ITEM_EXIST,
    SYSCALL_ERROR,
	CONFIG_ERROR,
    HANDLE_INCOMPLETE,
    UNKNOWN_ERROR,
};


enum process_code {
	UNKNOWN_PKT = 100,
};
#endif
