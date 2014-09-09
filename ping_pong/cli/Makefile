SHELL = /bin/sh
CC    = gcc
CFLAGS       = -Wall -I../../
DEBUGFLAGS   = -g -O0 -D_DEBUG -DDEBUG
RELEASEFLAGS = -O2 -D NDEBUG -fwhole-program

USE_FLAGS = $(RELEASEFLAGS)
ifeq ($(DEBUG), y)
  CFLAGS := $(CFLAGS) $(DEBUGFLAGS)
else
  CFLAGS := $(CFLAGS) $(RELEASEFLAGS)
endif


TARGET  = pp_cmd_cli
SOURCES = $(shell echo *.c)
HEADERS = $(shell echo *.h)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) -o $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) *.o *.so
