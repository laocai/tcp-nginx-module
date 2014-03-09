SHELL = /bin/sh
CC    = gcc
CFLAGS       = -fPIC -Wall
DEBUGFLAGS   = -g -O0 -D_DEBUG -DDEBUG
RELEASEFLAGS = -O2 -DNDEBUG
LDFLAGS      = -shared

USE_FLAGS = $(RELEASEFLAGS)
ifeq ($(DEBUG), y)
  CFLAGS := $(CFLAGS) $(DEBUGFLAGS)
else
  CFLAGS := $(CFLAGS) $(RELEASEFLAGS)
endif


TARGET  = pp.so
SOURCES = $(shell echo *.c)
HEADERS = $(shell echo *.h)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f *.o *.so
