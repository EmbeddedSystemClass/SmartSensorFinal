CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g $(shell root-config --cflags) -I.
LDFLAGS=-g $(shell root-config --ldflags)
LDLIBS=$(shell root-config --libs)

all: smartsensor

smartsensor:
	SRCS=*/*.cpp
	OBJS=$(subst .cpp,.o,$(SRCS))
    $(CXX) $(LDFLAGS) $(CPPFLAGS) -o smartsensor $(OBJS) $(LDLIBS) 

lncf:
	SRCS=lncf/*.cpp
	OBJS=$(subst .cpp,.o,$(SRCS))
	$(CXX) $(LDFLAGS) $(CPPFLAGS) -o smartsensor $(OBJS) $(LDLIBS) 

clean:
    $(RM) $(OBJS)

distclean: clean
    $(RM) tool