#ifndef MODBUS_H
#define MODBUS_H

#include <stdint.h>
#include <string>

#define READ_COIL_STATUS            0x01
#define READ_INPUT_STATUS           0x02
#define READ_HOLDING_REGISTERS      0x03
#define READ_INPUT_REGISTERS        0x04
#define FORCE_SINGLE_COIL           0x05
#define PRESET_SINGLE_REGISTER      0x06
#define READ_EXCEPTION_STATUS       0x07
#define FETCH_COMM_EVENT_COUNTER    0x0B
#define FORCE_MULTIPLE_COILS        0x0F
#define PRESET_MULTIPLE_REGISTERS   0x10
#define REPORT_SLAVE_ID             0x11

#define COILS_OFFSET                1
#define INPUTS_OFFSET               10001
#define INPUT_REGS_OFFSET           30001
#define HLD_REGS_OFFSET             40001

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

struct modbus_exception_response {
    struct modbus_tcp_generic generic_header;
    uint8_t coil_data;
} __attribute__((packed));

struct modbus_event_counter_response {
    struct modbus_tcp_generic generic_header;
    uint16_t status;
    uint16_t event_count;
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

struct modbus_report_slave_id_response {
    struct modbus_tcp_generic generic_header;
    uint8_t byte_count;
    uint8_t slave_id;
    uint8_t run_indicator_status;
    uint8_t *additional_data;
} __attribute__((packed));

struct modbus_aggregate {
    uint8_t function_code;
    void *query;
    void *response;
};

struct modbus_tcp_generic *get_modbus_tcp_generic(const uint8_t *payload);
struct modbus_read_query *get_modbus_read_query(const uint8_t *payload);
struct modbus_read_response *get_modbus_read_response(const uint8_t *payload);
struct modbus_single_write *get_modbus_single_write(const uint8_t *payload);
struct modbus_exception_response *get_modbus_exception_response(
    const uint8_t *payload);
struct modbus_event_counter_response *get_modbus_event_counter_response(
    const uint8_t *payload);
struct modbus_multiple_write_query *get_modbus_multiple_write_query(
    const uint8_t *payload);
struct modbus_multiple_write_response *get_modbus_multiple_write_response(
    const uint8_t *payload);
struct modbus_report_slave_id_response *get_modbus_report_slave_id_response(
    const uint8_t *payload);

std::string get_modbus_tcp_generic_string(const struct modbus_tcp_generic
                                          *modbus_struct);
std::string get_modbus_read_query_string(const struct modbus_read_query
                                         *modbus_struct);
std::string get_modbus_read_response_string(const struct modbus_read_response
                                            *modbus_struct);
std::string get_modbus_single_write_string(const struct modbus_single_write
                                           *modbus_struct);
std::string get_modbus_multiple_write_query_string(
    const struct modbus_multiple_write_query *modbus_struct);
std::string get_modbus_multiple_write_response_string(
    const struct modbus_multiple_write_response *modbus_struct);

void display_modbus_tcp_generic(const struct modbus_tcp_generic *modbus_struct,
                                bool query_packet);
void display_modbus_read_query(const struct modbus_read_query *modbus_struct);
void display_modbus_read_response(const struct modbus_read_response
                                  *modbus_struct);
void display_modbus_event_counter_response(
    const struct modbus_event_counter_response *modbus_struct);
void display_modbus_single_write(const struct modbus_single_write
                                 *modbus_struct, bool query_packet);
void display_modbus_exception_response(const struct modbus_exception_response
                                       *modbus_struct);
void display_modbus_multiple_write_query(
    const struct modbus_multiple_write_query *modbus_struct);
void display_modbus_multiple_write_response(
    const struct modbus_multiple_write_response *modbus_struct);

#endif
