#ifndef MODBUS_H
#define MODBUS_H

#include <stdint.h>

#define READ_COIL_STATUS            0x01
#define READ_INPUT_STATUS           0x02
#define READ_HOLDING_REGISTERS      0x03
#define READ_INPUT_REGISTERS        0x04
#define FORCE_SINGLE_COIL           0x05
#define PRESET_SINGLE_REGISTER      0x06
#define READ_EXCEPTION_STATUS       0x07
#define FORCE_MULTIPLE_COILS        0x0F
#define PRESET_MULTIPLE_REGISTERS   0x10
#define REPORT_SLAVE_ID             0x11

struct modbus_tcp_generic {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t unit_id;
    uint8_t function_code;
} __attribute__((packed));

struct modbus_read_query {
    struct modbus_tcp_generic generic_header;
    uint16_t starting_address;
    uint16_t num_of_points;
} __attribute__((packed));

struct modbus_read_response {
    struct modbus_tcp_generic generic_header;
    uint8_t byte_count;
    uint8_t *data;
} __attribute__((packed));

struct modbus_single_write {
    struct modbus_tcp_generic generic_header;
    uint16_t address;
    uint16_t value;
} __attribute__((packed));

struct modbus_multiple_write_query {
    struct modbus_tcp_generic generic_header;
    uint16_t starting_address;
    uint16_t num_of_points;
    uint8_t byte_count;
    uint8_t *data;
} __attribute__((packed));

struct modbus_multiple_write_response {
    struct modbus_tcp_generic generic_header;
    uint16_t starting_address;
    uint16_t num_of_points;
} __attribute__((packed));

void get_modbus_read_query(struct modbus_read_query *modbus_struct,
                           const uint8_t *payload);
void get_modbus_read_response(struct modbus_read_response *modbus_struct,
                              const uint8_t *payload);
void get_modbus_single_write(struct modbus_single_write *modbus_struct,
                             const uint8_t *payload);
void get_modbus_multiple_write_query(
    struct modbus_multiple_write_query *modbus_struct, const uint8_t *payload);
void get_modbus_multiple_write_response(
    struct modbus_multiple_write_response *modbus_struct,
    const uint8_t *payload);

#endif
