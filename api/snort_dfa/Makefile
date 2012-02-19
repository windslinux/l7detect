TARGET = test$(PREFIX)
DTSRC = $(wildcard *.c)
OBJ_DIR=${PWD}
OBJS = $(addprefix $(OBJ_DIR)/, $(DTSRC:%.c=%.o))
CFLAGS_LOCAL = -I ./
CC = gcc

%.o:%.c
	${CC} -c -Wall -g -O2 ${CFLAGS_LOCAL} $<
ALL:${OBJS}
	${CC} -o ${TARGET} ${OBJS}
clean:
	rm -f *.o ${TARGET}
