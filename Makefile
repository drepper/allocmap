CC = gcc
CXX = g++
CFLAGS = $(WARN) $(OPT) $(DEBUG) $(DEFS)
CXXFLAGS = $(WARN) $(OPT) $(DEBUG) $(DEFS)
WARN = -Wall
OPT = -Og
DEBUG = -g
DEFS = -D_GNU_SOURCE

SRCS = allocmap.cc xmalloc.c
OBJS = allocmap.o xmalloc.o
LIBS = -ldw -lelf

.PHONY: all clean
all: allocmap

allocmap: $(OBJS)
	$(CXX) -o $@ $^ $(LIBS)

clean:
	-rm -f allocmap $(OBJS)
