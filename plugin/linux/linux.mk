sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification
LIBS_NAME := pde_engine.so lde_engine.so sde_engine.so

pde_engine.so-OBJS := pde_engine.o engine_comm.o
pde_engine.so-FLAGS := -fPIC

sde_engine.so-OBJS := sde_engine.o engine_comm.o
sde_engine.so-FLAGS := -fPIC
sde_engine.so-LDFLAG := -lsnort_dfa

lde_engine.so-OBJS := lde_engine.o ldlua_register.o ldlua_pkb.o engine_comm.o ldlua_session.o
lde_engine.so-FLAGS := -I L$(LIBLUA_DIR)/include -fPIC
lde_engine.so-LDFLAG := -L$(LIBLUA_DIR)/lib -llua

OBJS_NAME := $(foreach obj, $(addsuffix -OBJS,$(LIBS_NAME)), $($(obj)))

DYNLIBS := $(addprefix $(DYNLIB_DIR)/,$(LIBS_NAME))
OBJS_$(d)  := $(addprefix $(OBJ_DIR)/,$(OBJS_NAME))

$(OBJS_$(d)):  CFLAGS_LOCAL := -I$(TOP)/include -I$(TOP)/api -I$(TOP)/core $($(notdir $(DYNLIB))-FLAGS)

#  standard component Makefile rules

DEPS_$(d)   :=  $(OBJS_$(d):.o=.d)

DYN_LIBS_LIST   :=  $(DYN_LIBS_LIST) $(DYNLIBS)

CLEAN_LIST := $(CLEAN_LIST)
CLEAN_LIST += $(OBJS_$(d))
CLEAN_LIST += $(DEPS_$(d))
CLEAN_LIST += $(DYNLIBS) *~

-include $(DEPS_$(d))

$(OBJ_DIR)/%.o: $(d)/%.c
	$(COMPILE)

$(DYNLIB):$(addprefix $(OBJ_DIR)/,$($(notdir $(DYNLIB))-OBJS))
	$(CC) -fPIC -shared -o $@ $(addprefix $(OBJ_DIR)/,$($(notdir $(DYNLIB))-OBJS)) $($(notdir $(DYNLIB))-LDFLAG) -L$(TOP)/build/obj/ -lapi

#  standard component Makefile footer
d   :=  $(dirstack_$(sp))
sp  :=  $(basename $(sp))
