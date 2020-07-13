#include <iostream>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>

#include "serial_sniffer.h"
#include "modbus.h"
#include "logger.h"
#include "prod_con_queue.h"

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

        if (baud_rate == 4800)
            baud_rate == B4800;
        else if (baud_rate == 9600)
            baud_rate == B9600;
        else if (baud_rate == 19200)
            baud_rate = B19200;

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

    int write_to_port(int port_fd, struct msg_buf *item)
    {
        write(port_fd, item->payload, item->length);

        return 0;
    }

    int read_query_frame()
    {
        uint8_t *read_buf;
        struct msg_buf *queue_item;
        uint8_t value;
        int buf_index;
        int n;
        int bytes_read;
        uint8_t function_code;
        uint8_t byte_count;
        uint16_t frame_length;

        read_buf = new uint8_t[BUFFER_SIZE];
        memset(read_buf, '\0', 6 * sizeof(uint8_t));

        buf_index = 6;
        bytes_read = 0;

        n = read(port1_fd, read_buf + buf_index, 2 * sizeof(uint8_t));
        buf_index += n;

        if (n == 1) {
            n = read(port1_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;
        }

        function_code = read_buf[7];

        switch (function_code) {
        case READ_COIL_STATUS:
            while (bytes_read < 4) {
                n = read(port1_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case READ_INPUT_STATUS:
            while (bytes_read < 4) {
                n = read(port1_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case READ_HOLDING_REGISTERS:
            while (bytes_read < 4) {
                n = read(port1_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case READ_INPUT_REGISTERS:
            while (bytes_read < 4) {
                n = read(port1_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case FORCE_SINGLE_COIL:
            while (bytes_read < 4) {
                n = read(port1_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case PRESET_SINGLE_REGISTER:
            while (bytes_read < 4) {
                n = read(port1_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case READ_EXCEPTION_STATUS:
            frame_length = 2;

            break;
        case DIAGNOSTICS:

            break;
        case FETCH_COMM_EVENT_COUNTER:
            frame_length = 2;

            break;
        case FETCH_COMM_EVENT_LOG:
            frame_length = 2;

            break;
        case FORCE_MULTIPLE_COILS:
            while (bytes_read < 5) {
                n = read(port1_fd, read_buf + buf_index, 
                    5 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            byte_count = read_buf[12];

            while (bytes_read < byte_count) {
                n = read(port1_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 7 + byte_count;

            break;
        case PRESET_MULTIPLE_REGISTERS:
            while (bytes_read < 5) {
                n = read(port1_fd, read_buf + buf_index, 
                    5 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            byte_count = read_buf[12];

            while (bytes_read < byte_count) {
                n = read(port1_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 7 + byte_count;

            break;
        case REPORT_SLAVE_ID:
            frame_length = 2;

            break;
        case READ_FILE_RECORD:
            break;
        case WRITE_FILE_RECORD:
            break;
        case MASK_WRITE_REGISTER:
            while (bytes_read < 6) {
                n = read(port1_fd, read_buf + buf_index, 
                    6 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 8;

            break;
        default:
            std::cout << "Function code decoding not yet implemented"
                << std::endl;

            return 0;
        }

        // read the CRC
        n = read(port1_fd, read_buf + buf_index, 2 * sizeof(uint8_t));
        buf_index += n;

        if (n == 1) {
            n = read(port1_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;
        }

        frame_length += 2;

        logger::modbus_packet_handler(read_buf);

        queue_item = new msg_buf;
        queue_item->payload = read_buf + 6;
        queue_item->length = frame_length;

        write_to_port(port2_fd, queue_item);

        delete[] read_buf;
        delete queue_item;

        return 0;
    }

    int read_response_frame()
    {
        uint8_t *read_buf;
        struct msg_buf *queue_item;
        int buf_index;
        int n;
        int bytes_read;
        uint8_t function_code;
        uint8_t byte_count;
        uint16_t frame_length;

        read_buf = new uint8_t[BUFFER_SIZE];
        memset(read_buf, '\0', 6 * sizeof(uint8_t));

        buf_index = 6;
        bytes_read = 0;

        n = read(port2_fd, read_buf + buf_index, 2 * sizeof(uint8_t));
        buf_index += n;

        if (n == 1) {
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;
        }

        function_code = read_buf[7];

        switch (function_code) {
        case READ_COIL_STATUS:
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;

            byte_count = read_buf[8];

            while (bytes_read < byte_count) {
                n = read(port2_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 3 + byte_count;

            break;
        case READ_INPUT_STATUS:
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;

            byte_count = read_buf[8];

            while (bytes_read < byte_count) {
                n = read(port2_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 3 + byte_count;

            break;
        case READ_HOLDING_REGISTERS:
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;

            byte_count = read_buf[8];

            while (bytes_read < byte_count) {
                n = read(port2_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 3 + byte_count;

            break;
        case READ_INPUT_REGISTERS:
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;

            byte_count = read_buf[8];

            while (bytes_read < byte_count) {
                n = read(port2_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 3 + byte_count;

            break;
        case FORCE_SINGLE_COIL:
            while (bytes_read < 4) {
                n = read(port2_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case PRESET_SINGLE_REGISTER:
            while (bytes_read < 4) {
                n = read(port2_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case READ_EXCEPTION_STATUS:
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;

            frame_length = 3;

            break;
        case DIAGNOSTICS:

            break;
        case FETCH_COMM_EVENT_COUNTER:
            while (bytes_read < 4) {
                n = read(port2_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case FETCH_COMM_EVENT_LOG:
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;

            byte_count = read_buf[8];

            while (bytes_read < byte_count) {
                n = read(port2_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 3 + byte_count;

            break;
        case FORCE_MULTIPLE_COILS:
            while (bytes_read < 4) {
                n = read(port2_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case PRESET_MULTIPLE_REGISTERS:
            while (bytes_read < 4) {
                n = read(port2_fd, read_buf + buf_index, 
                    4 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 6;

            break;
        case REPORT_SLAVE_ID:
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;

            byte_count = read_buf[8];

            while (bytes_read < byte_count) {
                n = read(port2_fd, read_buf + buf_index,
                         byte_count * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 3 + byte_count;

            break;
        case READ_FILE_RECORD:
            break;
        case WRITE_FILE_RECORD:
            break;
        case MASK_WRITE_REGISTER:
            while (bytes_read < 6) {
                n = read(port2_fd, read_buf + buf_index, 
                    6 * sizeof(uint8_t) - bytes_read);
                buf_index += n;
                bytes_read += n;
            }

            frame_length = 8;

            break;
        default:
            std::cout << "Function code decoding not yet implemented"
                << std::endl;
        }

        // read the CRC
        n = read(port2_fd, read_buf + buf_index, 2 * sizeof(uint8_t));
        buf_index += n;

        if (n == 1) {
            n = read(port2_fd, read_buf + buf_index, sizeof(uint8_t));
            buf_index += n;
        }

        frame_length += 2;

        logger::modbus_packet_handler(read_buf);

        queue_item = new msg_buf;
        queue_item->payload = read_buf + 6;
        queue_item->length = frame_length;

        write_to_port(port1_fd, queue_item);

        delete[] read_buf;
        delete queue_item;

        return 0;
    }

    int run()
    {
        std::cout << "starting to run" << std::endl;

        while (true) {
            read_query_frame();
            read_response_frame();
        }

        return 0;
    }

    void close_sniffer()
    {
        close(port1_fd);
        close(port2_fd);
    }
}
