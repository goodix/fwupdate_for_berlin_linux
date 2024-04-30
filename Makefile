CC = gcc
CFLAGS = -Wall
SRC = main.c fwupdate.c log_wrapper.c 
TARGET = fwupdate

all: $(TARGET)
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^
clean:
	rm -f $(TARGET)
