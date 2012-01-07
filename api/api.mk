sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

LIBRARY := $(OBJ_DIR)/libapi.a

API_OBJS = $(OBJ_DIR)/log.o
API_OBJS += $(OBJ_DIR)/module_manage.o
API_OBJS += $(OBJ_DIR)/tag_manage.o
API_OBJS += $(OBJ_DIR)/hash_table.o
API_OBJS += $(OBJ_DIR)/zone.o
API_OBJS += $(OBJ_DIR)/helper.o

OBJS_$(d)  :=  $(API_OBJS)

API_CFLAGS_LOCAL := -I$(d) -I$(TOP)/api -fPIC

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
sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

dir = $(d)/snort_dfa
include $(dir)/snort_dfa.mk

#  standard component Makefile footer

d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))


d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))
