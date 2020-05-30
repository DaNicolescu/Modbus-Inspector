#ifndef LOGGER_H
#define LOGGER_H

#define ETH_HDR_LEN		    0x0E

#define READ_COIL_STATUS	    0x01
#define READ_INPUT_STATUS	    0x02
#define READ_HOLDING_REGISTERS	    0x03
#define READ_INPUT_REGISTERS	    0x04
#define FORCE_SINGLE_COIL	    0x05
#define PRESET_SINGLE_REGISTER	    0x06
#define READ_EXCEPTION_STATUS	    0x07
#define FORCE_MULTIPLE_COILS	    0x0F
#define PRESET_MULTIPLE_REGISTERS   0x10
#define REPORT_SLAVE_ID		    0x11

struct modbus_tcp {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t unit_id;
    uint8_t function_code;
} __attribute__((packed));

#endif
