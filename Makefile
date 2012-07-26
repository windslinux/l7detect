TOP:=${PWD}

LDFLAGS_GLOBAL=

#.PHONY: head_links clean back update version tags cstags
#  standard common Makefile fragment
all: all_targets

include $(TOP)/build/extra.mk

#  include relevant component Makefile fragments
dir:=$(TOP)/lib
include $(dir)/lib.mk

dir:=$(TOP)/cli
include $(dir)/cli.mk

dir:=$(TOP)/core
include $(dir)/core.mk

dir:=$(TOP)/test
include $(dir)/test.mk

dir:=$(TOP)/sys
include $(dir)/sys.mk

dir:=$(TOP)/api
include $(dir)/api.mk

dir:=$(TOP)/plugin
include $(dir)/plugin.mk

TARGET = l7detect$(PREFIX)

LIBS_LIST := $(LIBS_LIST) $($(TARGET)-LIBS)

CFLAGS_LOCAL = -g -O2 -W -Wall -Wno-unused-parameter
CFLAGS_LOCAL += $($(TARGET)-FLAGS)

CFLAGS_GLOBAL += -I$(TOP)/include -I$(LIBLUA_DIR)/include
LDFLAGS_GLOBAL += $(LIBEVENT) -L$(LIBLUA_DIR)/lib -llua -L$(CTHREADPOOL_DIR) -lcthreadpool -lpthread -lpcap -ldl -lm -lrt
include $(TOP)/build/application.mk

CLEAN_LIST += $(OBJS)
CLEAN_LIST += $(OBJS:.o=.d)
CLEAN_LIST += $(GEN_C_FILES)

all_targets:$(DYNLIB_DIR)
	for t in $(DYN_LIBS_LIST); do $(MAKE) DYNLIB=$$t application-target|| exit -1;done
zip:
	git archive --format=zip --prefix=l7detect/ HEAD > l7detect.zip
cstags:
	find $(PWD) -name "*.[ch]" -type f > cscope.files;cscope -b

clean:
	rm -f $(TARGET)
	rm -f $(CLEAN_LIST)

clobber: clean
	rm -rf $(OBJ_DIR) $(DYNLIB_DIR)


