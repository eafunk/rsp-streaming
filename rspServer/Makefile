TARGET = rspServer
CC=gcc
CFLAGS = -g3
SRC = $(wildcard *.c)
INC = $(wildcard *.h)
LDFLAGS = -lc -lm -lcrypto -lpthread

all: $(TARGET)

$(TARGET): $(SRC) $(INC)
	$(CC) -o $(TARGET) $(CFLAGS) $(SRC) $(INC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
	
install:
	chmod 775 $(TARGET)
	cp -ut /usr/local/bin/ $(TARGET)
