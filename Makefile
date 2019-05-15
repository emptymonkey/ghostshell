CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Os
OBJS = string_to_vector.o 

all: ghostshell

ghostshell: ghostshell.c $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o ghostshell ghostshell.c

string_to_vector: string_to_vector.c
	$(CC) $(CFLAGS) -c -o string_to_vector.o string_to_vector.c

clean: 
	rm ghostshell $(OBJS)
