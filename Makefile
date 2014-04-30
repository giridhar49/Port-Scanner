CC=g++
CPFLAGS=-g -Wall  -std=gnu++0x
LDFLAGS=  -lcrypto -lpcap -lpthread 


SRC= portscanner.cpp args_setup.cpp
OBJ=$(SRC:.c=.o)
BIN=Test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
