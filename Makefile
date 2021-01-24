CC?=gcc

CFLAGS+=-Wall -Werror -ggdb
NAME=pling

pling: main.o
	$(CC) ${CFLAGS} main.o -o ${NAME} ${LDFLAGS}

main.o: main.h ether.h list.h times.h

clean:
	rm -f *.o
	rm -f ${NAME}
