sp              :=  $(sp).x
dirstack_$(sp)  :=  $(d)
d               :=  $(dir)

#  component specification

LIBRARY := $(OBJ_DIR)/libsnort_dfa.a

SNORT_DFA_OBJS += $(OBJ_DIR)/acsmx.o
SNORT_DFA_OBJS = $(OBJ_DIR)/acsmx2.o
SNORT_DFA_OBJS += $(OBJ_DIR)/bnfa_search.o
SNORT_DFA_OBJS += $(OBJ_DIR)/profiler.o
SNORT_DFA_OBJS += $(OBJ_DIR)/sfksearch.o
SNORT_DFA_OBJS += $(OBJ_DIR)/str_search.o
SNORT_DFA_OBJS += $(OBJ_DIR)/mpse.o

OBJS_$(d)  :=  $(SNORT_DFA_OBJS)

SNORT_DFA_CFLAGS_LOCAL := -I$(d) -fPIC -Wno-missing-field-initializers -Wno-unused-but-set-variable -Wno-sign-compare

$(OBJS_$(d)):  CFLAGS_LOCAL := $(SNORT_DFA_CFLAGS_LOCAL)


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
