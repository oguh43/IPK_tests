CC := gcc
CFLAGS := -D_XOPEN_SOURCE=700 -Wall -Wextra -std=c99 -pedantic -Werror -Wconversion -Wsign-conversion -Wdouble-promotion -Wpadded -Wpacked -Wunsafe-loop-optimizations -Wstack-usage=2048
LDFLAGS := -lpthread

TARGET := test_ipk_rdt
SRC := test_ipk_rdt.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
