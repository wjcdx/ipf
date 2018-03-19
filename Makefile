
# compile variables
CC = gcc
#CC = arm-hsan-linux-uclibcgnueabi-gcc
#CC = arm-linux-gnueabi-gcc
CFLAGS += -Wall
#CFLAGS += -DDEBUG
#CFLAGS += -g

#LDFLAGS += -static
LDFLAGS += -lpthread
#LDFLAGS += -lc

# build target
TARGET  = ipf
OBJECTS = main.o util.o conntrack.o nat.o DNAT.o

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@ 

clean:
	rm -rf *.o $(TARGET)

.PHONY: all clean

