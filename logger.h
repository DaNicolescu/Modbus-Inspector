#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <vector>
#include <utility>
#include <unordered_map>

#define ETH_HDR_LEN                 0x0E

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

// config file
#define XLS_CONFIG_FILE_NAME            "../config.xls"
#define XLS_DEVICES_SHEET_NAME          "devices"
#define XLS_DEVICE_ADDRESSES_SHEET_NAME "device "

#define XLS_DEVICES_NUM_OF_COLUMNS                  10
#define XLS_DEVICES_SLAVE_ID_COLUMN                 1
#define XLS_DEVICES_DEVICE_NAME_COLUMN              2
#define XLS_DEVICES_READ_COILS_COLUMN               3
#define XLS_DEVICES_WRITE_COILS_COLUMN              4
#define XLS_DEVICES_INPUTS_COLUMN                   5
#define XLS_DEVICES_READ_HLD_REGS_COLUMN            6
#define XLS_DEVICES_WRITE_HLD_REGS_COLUMN           7
#define XLS_DEVICES_INPUT_REGS_COLUMN               8
#define XLS_DEVICES_GENERIC_FUNCS_COLUMN            9
#define XLS_DEVICES_SPECIFIC_FUNCS_COLUMN           10

#define XLS_DEVICE_ADDRESSES_NUM_OF_COLUMNS         6
#define XLS_DEVICE_ADDRESSES_ADDRESS_COLUMN         1
#define XLS_DEVICE_ADDRESSES_RW_COLUMN              2
#define XLS_DEVICE_ADDRESSES_DESCRIPTION_COLUMN     3
#define XLS_DEVICE_ADDRESSES_SIZE_COLUMN            4
#define XLS_DEVICE_ADDRESSES_TYPE_COLUMN            5
#define XLS_DEVICE_ADDRESSES_RANGE_COLUMN           6

#define XLS_ADDRESS_READ                            "R"
#define XLS_ADDRESS_READ_WRITE                      "RW"

#define XLS_INT_TYPE_STR                            "int"
#define XLS_UINT_TYPE_STR                           "uint"
#define XLS_FLOAT_TYPE_STR                          "float"
#define XLS_INT_TYPE                                1
#define XLS_UINT_TYPE                               2
#define XLS_FLOAT_TYPE                              4

#define XLS_8BIT_ADDRESS_SIZE_STR                   "8"
#define XLS_16BIT_ADDRESS_SIZE_STR                  "16"
#define XLS_8BIT_ADDRESS_SIZE                       1
#define XLS_16BIT_ADDRESS_SIZE                      2

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

union value_type {
    int i;
    float f;
};

struct address_struct {
    uint16_t address;
    bool write;
    std::string description;
    uint8_t size;
    uint8_t type;
    std::vector<union value_type> possible_values;
    std::vector<std::pair<union value_type, union value_type>> possible_ranges;
};

struct device_struct {
    uint8_t id;
    std::string name;
    std::string read_coils;
    std::string write_coils;
    std::string inputs;
    std::string read_holding_registers;
    std::string write_holding_registers;
    std::string input_registers;
    std::vector<uint8_t> generic_supported_functions;
    std::vector<uint8_t> specific_supported_functions;
    std::unordered_map<uint16_t, struct address_struct*> addresses_map;

    bool supported_function(uint8_t function);
    struct address_struct *get_address(uint16_t address);
};

#endif
