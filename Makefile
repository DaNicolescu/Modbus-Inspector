CXX=g++
RM=rm -f
LDLIBS=-lxlsreader -lpcap -pthread `mariadb_config --libs`

SRCS=logger.cpp serial_sniffer.cpp tcp_sniffer.cpp XlsReader.cpp device_struct.cpp modbus.cpp config.cpp utils.cpp db.cpp prod_con_queue.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

all: logger

logger: $(OBJS)
	$(CXX) -o logger $(OBJS) $(LDLIBS) -Wl,-R/usr/local/lib

logger.o: logger.cpp logger.h

XlsReader.o: XlsReader.cpp XlsReader.h

serial_sniffer.o: serial_sniffer.cpp serial_sniffer.h

tcp_sniffer.o: tcp_sniffer.cpp tcp_sniffer.h

device_struct.o: device_struct.cpp device_struct.h

modbus.o: modbus.cpp modbus.h

config.o: config.cpp config.h

utils.o: utils.cpp utils.h

prod_con_queue.o: prod_con_queue.cpp prod_con_queue.h

db.o: db.cpp db.h
	$(CXX) -c -o db.o db.cpp `mariadb_config --cflags`

clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) logger
