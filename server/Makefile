INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/
all:
	gcc -I$(INC) -L$(LIB) -o cryptserv crypto_server.c -lssl -lcrypto -ldl
