sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

LIBRARY := $(OBJ_DIR)/libcore.a

API_OBJS = $(OBJ_DIR)/main.o
API_OBJS += $(OBJ_DIR)/conf.o
API_OBJS += $(OBJ_DIR)/pcap_live.o
API_OBJS += $(OBJ_DIR)/pcap_read.o
API_OBJS += $(OBJ_DIR)/recv.o
API_OBJS += $(OBJ_DIR)/decap.o
API_OBJS += $(OBJ_DIR)/process.o
API_OBJS += $(OBJ_DIR)/session_frm.o
API_OBJS += $(OBJ_DIR)/ff_table.o
API_OBJS += $(OBJ_DIR)/sf_plugin.o
API_OBJS += $(OBJ_DIR)/lua_ci.o

OBJS_$(d)  :=  $(API_OBJS)

API_CFLAGS_LOCAL := -I$(d) -I$(LIBEVENT_DIR)/install-dir/include -I$(TOP)/api -I$(TOP)/sys -I$(TOP)/test

$(OBJS_$(d)):  CFLAGS_LOCAL := $(API_CFLAGS_LOCAL)


#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

LIBS_LIST   :=  $(LIBS_LIST) $(LIBRARY)

CLEAN_LIST := $(CLEAN_LIST)
CLEAN_LIST += $(OBJS_$(d))
CLEAN_LIST += $(DEPS_$(d))
CLEAN_LIST += $(LIBRARY) *~

-include $(DEPS_$(d))

$(LIBRARY): $(OBJS_$(d))
	rm -f $@
	$(AR) -cr $@ $^

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))
