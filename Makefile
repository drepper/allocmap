CC = gcc
CXX = g++
CFLAGS = $(WARN) $(OPT) $(DEBUG)
CXXFLAGS = $(WARN) $(OPT) $(DEBUG)
WARN = -Wall
OPT = -Og
DEBUG = -g

SRCS = allocmap.cc xmalloc.c
OBJS = allocmap.o xmalloc.o
LIBS = -ldw -lelf

.PHONY: all clean
all: allocmap

allocmap: $(OBJS)
	$(CXX) -o $@ $^ $(LIBS)

clean:
	-rm -f allocmap $(OBJS)
