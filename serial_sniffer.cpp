#include <iostream>
#include <fcntl.h> // Contains file controls like O_RDWR
#include <errno.h> // Error integer and strerror() function
#include <termios.h> // Contains POSIX terminal control definitions
#include <unistd.h> // write(), read(), close()
#include <string.h>

#include "serial_sniffer.h"

namespace serial_sniffer {
    std::string port1;
    std::string port2;

    int port1_fd;
    int port2_fd;

    int init(std::string port1, std::string port2, unsigned int baud_rate,
        unsigned int data_bits, unsigned int parity_bit,
        unsigned int stop_bits)
    {
        struct termios port1_tty;
        struct termios port2_tty;

        port1_fd = open(port1.c_str(), O_RDWR);
        port2_fd = open(port2.c_str(), O_RDWR);

        memset(&port1_tty, 0, sizeof(struct termios));
        memset(&port2_tty, 0, sizeof(struct termios));

        if(tcgetattr(port1_fd, &port1_tty) != 0) {
            std::cout << "error " << errno << " from tcgetattr: "
                << strerror(errno) << std::endl;

            return 1;
        }

        if(tcgetattr(port2_fd, &port2_tty) != 0) {
            std::cout << "error " << errno << " from tcgetattr: "
                << strerror(errno) << std::endl;

            return 1;
        }

        if (parity_bit == NO_PARITY) {
            port1_tty.c_cflag &= ~PARENB;
            port2_tty.c_cflag &= ~PARENB;
        } else if (parity_bit == EVEN_PARITY) {
            port1_tty.c_cflag |= PARENB;
            port1_tty.c_cflag &= ~PARODD;
            port2_tty.c_cflag |= PARENB;
            port2_tty.c_cflag &= ~PARODD;
        } else if (parity_bit == ODD_PARITY) {
            port1_tty.c_cflag |= PARENB;
            port1_tty.c_cflag |= PARODD;
            port2_tty.c_cflag |= PARENB;
            port2_tty.c_cflag |= PARODD;
        }

        if (stop_bits == ONE_STOP_BIT) {
            port1_tty.c_cflag &= ~CSTOPB;
            port2_tty.c_cflag &= ~CSTOPB;
        } else if (stop_bits == TWO_STOP_BITS) {
            port1_tty.c_cflag |= CSTOPB;
            port2_tty.c_cflag |= CSTOPB;
        }

        port1_tty.c_cflag &= ~CSIZE;
        port2_tty.c_cflag &= ~CSIZE;

        port1_tty.c_cflag |= data_bits;
        port2_tty.c_cflag |= data_bits;

        // Disable RTS/CTS hardware flow control
        port1_tty.c_cflag &= ~CRTSCTS; 
        port2_tty.c_cflag &= ~CRTSCTS;

        // Turn on READ & ignore ctrl lines
        port1_tty.c_cflag |= CREAD | CLOCAL; 
        port2_tty.c_cflag |= CREAD | CLOCAL; 

        port1_tty.c_lflag &= ~ICANON;
        port1_tty.c_lflag &= ~ECHO;
        port1_tty.c_lflag &= ~ECHOE;
        port1_tty.c_lflag &= ~ECHONL;
        port1_tty.c_lflag &= ~ISIG;
        port1_tty.c_iflag &= ~(IXON | IXOFF | IXANY);
        port1_tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR
                               | IGNCR | ICRNL);
        port2_tty.c_lflag &= ~ICANON;
        port2_tty.c_lflag &= ~ECHO;
        port2_tty.c_lflag &= ~ECHOE;
        port2_tty.c_lflag &= ~ECHONL;
        port2_tty.c_lflag &= ~ISIG;
        port2_tty.c_iflag &= ~(IXON | IXOFF | IXANY);
        port2_tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR
                               | IGNCR | ICRNL);

        port1_tty.c_oflag &= ~OPOST;
        port1_tty.c_oflag &= ~ONLCR;
        port2_tty.c_oflag &= ~OPOST;
        port2_tty.c_oflag &= ~ONLCR;

        port1_tty.c_cc[VTIME] = 0;
        port1_tty.c_cc[VMIN] = 1;
        port2_tty.c_cc[VTIME] = 0;
        port2_tty.c_cc[VMIN] = 1;

        cfsetispeed(&port1_tty, baud_rate);
        cfsetospeed(&port1_tty, baud_rate);
        cfsetispeed(&port2_tty, baud_rate);
        cfsetospeed(&port2_tty, baud_rate);

        if (tcsetattr(port1_fd, TCSANOW, &port1_tty) != 0) {
            std::cout << "Error " << errno << " from tcsetattr: "
                << strerror(errno) << std::endl;

            return 1;
        }

        if (tcsetattr(port2_fd, TCSANOW, &port2_tty) != 0) {
            std::cout << "Error " << errno << " from tcsetattr: "
                << strerror(errno) << std::endl;

            return 1;
        }

        return 0;
    }

    int run()
    {
        char read_buf [256];
        memset(&read_buf, '\0', sizeof(read_buf));

        int n = read(port1_fd, &read_buf, sizeof(read_buf));

        std::cout << "read " << n << " bytes from serial port: "
            << unsigned(read_buf[0]) << ", " << unsigned(read_buf[1]) << ", "
            << unsigned(read_buf[2]) << ", " << unsigned(read_buf[3])
            << std::endl;

        return 0;
    }

    void close_sniffer()
    {
        close(port1_fd);
        close(port2_fd);
    }
}
