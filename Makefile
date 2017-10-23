RM=rm -f
CC=gcc
LARGS=-lpthread -ldl
all:
	$(CC) -o srarpd srarpd.c sqlite3.c -I. $(LARGS)
clean:
	$(RM) srarpd *.o
