#ifndef SERIAL_SNIFFER_H
#define SERIAL_SNIFFER_H

#include <string>

#define BUFFER_SIZE         256

#define NO_PARITY           0
#define ODD_PARITY          1
#define EVEN_PARITY         2

#define ONE_STOP_BIT        1
#define TWO_STOP_BITS       2

struct msg_buf;

namespace serial_sniffer {
    int init(std::string port1, std::string port2, unsigned int baud_rate,
        unsigned int data_bits, unsigned int parity_bit,
        unsigned int stop_bits);
    int write_to_port(int port_fd, struct msg_buf *item);
    int read_query_frame();
    int read_response_frame();
    int run();
    void close_sniffer();
};

#endif
