CC=gcc
CFLAGS=-I.
OBJS = des.o bitarray.o feistel_bits.o
SRC  = des.c bitarray.c feistel_bits.c
TARGET = fpe

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(SRC)

clean:
	rm $(OBJS)
