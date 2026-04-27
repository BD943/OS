CC ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11 -D_POSIX_C_SOURCE=200809L -g
LDFLAGS ?=

TARGET := city_manager
OBJS := main.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

main.o: main.c

clean:
	rm -f $(TARGET) $(OBJS)
