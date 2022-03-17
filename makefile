
CC=gcc
CFLAGS=-c -Wall -g 
LDFLAGS=-g 
OPENSSL=

all: irusb_app.o process_uartstr.o 
	$(CC) $(LDFLAGS) irusb_app.o  process_uartstr.o  -o irusb $(OPENSSL)
    
irusb_app.o: irusb_app.c
	$(CC) $(CFLAGS) irusb_app.c

process_uartstr.o: process_uartstr.c
	$(CC) $(CFLAGS) process_uartstr.c


