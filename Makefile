CXX=g++
RM=rm -f
LDLIBS=-lxlsreader -lpcap

SRCS=logger.cpp XlsReader.cpp device_struct.cpp modbus.cpp config.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

all: logger

logger: $(OBJS)
	$(CXX) -o logger $(OBJS) $(LDLIBS) -Wl,-R/usr/local/lib

looger.o: logger.cpp logger.h

XlsReader.o: XlsReader.cpp XlsReader.h

device_struct.o: device_struct.cpp device_struct.h

modbus.o: modbus.cpp modbus.h

config.o: config.cpp config.h

clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) logger
