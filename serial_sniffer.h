#ifndef SERIAL_SNIFFER_H
#define SERIAL_SNIFFER_H

#include <string>

#define NO_PARITY           0
#define EVEN_PARITY         1
#define ODD_PARITY          2

#define ONE_STOP_BIT        0
#define TWO_STOP_BITS       1

namespace serial_sniffer {
    int init(std::string port1, std::string port2, unsigned int baud_rate,
        unsigned int data_bits, unsigned int parity_bit,
        unsigned int stop_bits);
    int run();
    void close_sniffer();
};

#endif
