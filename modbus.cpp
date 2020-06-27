#include <iostream>
#include <string.h>
#include <netinet/in.h>

#include "modbus.h"
#include "utils.h"

void reorder_modbus_tcp_generic_bytes(struct modbus_tcp_generic *modbus_struct)
{
    modbus_struct->transaction_id = htons(modbus_struct->transaction_id);
    modbus_struct->protocol_id = htons(modbus_struct->protocol_id);
    modbus_struct->length = htons(modbus_struct->length);
}

struct modbus_tcp_generic *get_modbus_tcp_generic(const uint8_t *payload)
{
    struct modbus_tcp_generic *modbus_struct;

    modbus_struct = new modbus_tcp_generic;

    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic));

    reorder_modbus_tcp_generic_bytes(modbus_struct);

    return modbus_struct;
}

struct modbus_read_query *get_modbus_read_query(const uint8_t *payload)
{
    struct modbus_read_query *modbus_struct;

    modbus_struct = new modbus_read_query;

    memcpy(modbus_struct, payload, sizeof(struct modbus_read_query));

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->starting_address = htons(modbus_struct->starting_address);
    modbus_struct->num_of_points = htons(modbus_struct->num_of_points);

    return modbus_struct;
}

struct modbus_read_response *get_modbus_read_response(const uint8_t *payload)
{
    struct modbus_read_response *modbus_struct;

    modbus_struct = new modbus_read_response;

    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic) + 1);

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->data = (uint8_t*) malloc(modbus_struct->byte_count);

    if (!modbus_struct->data) {
        std::cout << "Failed to allocate memory" << std::endl;

        return NULL;
    }

    memcpy(modbus_struct->data, payload + sizeof(struct modbus_tcp_generic) + 1,
           modbus_struct->byte_count);

    return modbus_struct;
}

struct modbus_single_write *get_modbus_single_write(const uint8_t *payload)
{
    struct modbus_single_write *modbus_struct;

    modbus_struct = new modbus_single_write;

    memcpy(modbus_struct, payload, sizeof(struct modbus_single_write));

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->address = htons(modbus_struct->address);
    modbus_struct->value = htons(modbus_struct->value);

    return modbus_struct;
}

struct modbus_exception_status_response *get_modbus_exception_status_response(
    const uint8_t *payload)
{
    struct modbus_exception_status_response *modbus_struct;

    modbus_struct = new modbus_exception_status_response;

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    return modbus_struct;
}

struct modbus_diagnostics *get_modbus_diagnostics(const uint8_t *payload)
{
    struct modbus_diagnostics *modbus_struct;

    modbus_struct = new modbus_diagnostics;

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->subfunction = htons(modbus_struct->subfunction);
    modbus_struct->data = htons(modbus_struct->data);

    return modbus_struct;
}

struct modbus_event_counter_response *get_modbus_event_counter_response(
    const uint8_t *payload)
{
    struct modbus_event_counter_response *modbus_struct;

    modbus_struct = new modbus_event_counter_response;

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->status = htons(modbus_struct->status);
    modbus_struct->event_count = htons(modbus_struct->event_count);

    return modbus_struct;
}

struct modbus_event_log_response *get_modbus_event_log_response(const uint8_t
                                                                *payload)
{
    struct modbus_event_log_response *modbus_struct;

    modbus_struct = new modbus_event_log_response;

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->status = htons(modbus_struct->status);
    modbus_struct->event_count = htons(modbus_struct->event_count);
    modbus_struct->message_count = htons(modbus_struct->message_count);

    return modbus_struct;
}

struct modbus_multiple_write_query *get_modbus_multiple_write_query(
    const uint8_t *payload)
{
    struct modbus_multiple_write_query *modbus_struct;

    modbus_struct = new modbus_multiple_write_query;

    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic) + 5);

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->starting_address = htons(modbus_struct->starting_address);
    modbus_struct->num_of_points = htons(modbus_struct->num_of_points);

    modbus_struct->data = (uint8_t*) malloc(modbus_struct->byte_count);

    if (!modbus_struct->data) {
        std::cout << "Failed to allocate memory" << std::endl;

        return NULL;
    }

    memcpy(modbus_struct->data, payload + sizeof(struct modbus_tcp_generic) + 5,
           modbus_struct->byte_count);

    return modbus_struct;
}

struct modbus_multiple_write_response *get_modbus_multiple_write_response(
    const uint8_t *payload)
{
    struct modbus_multiple_write_response *modbus_struct;

    modbus_struct = new modbus_multiple_write_response;

    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic) + 4);

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->starting_address = htons(modbus_struct->starting_address);
    modbus_struct->num_of_points = htons(modbus_struct->num_of_points);

    return modbus_struct;
}

struct modbus_report_slave_id_response *get_modbus_report_slave_id_response(
    const uint8_t *payload)
{
    struct modbus_report_slave_id_response *modbus_struct;

    modbus_struct = new modbus_report_slave_id_response;

    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic) + 3);

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->additional_data = (uint8_t*)
        malloc(modbus_struct->byte_count - 2);

    if (!modbus_struct->additional_data) {
        std::cout << "Failed to allocate memory" << std::endl;

        return NULL;
    }

    memcpy(modbus_struct->additional_data, payload
           + sizeof(struct modbus_tcp_generic) + 3,
           modbus_struct->byte_count - 2);

    return modbus_struct;
}

struct modbus_mask_write *get_modbus_mask_write(const uint8_t *payload)
{
    struct modbus_mask_write *modbus_struct;

    modbus_struct = new modbus_mask_write;

    memcpy(modbus_struct, payload, sizeof(struct modbus_mask_write));

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    modbus_struct->address = htons(modbus_struct->address);
    modbus_struct->and_mask = htons(modbus_struct->and_mask);
    modbus_struct->or_mask = htons(modbus_struct->or_mask);

    return modbus_struct;
}

struct modbus_exception *get_modbus_exception(const uint8_t *payload)
{
    struct modbus_exception *modbus_struct;

    modbus_struct = new modbus_exception;

    memcpy(modbus_struct, payload, sizeof(struct modbus_exception));

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

    return modbus_struct;
}

std::string get_event_log_event_string(uint8_t event)
{
    std::string event_string = byte_to_binary_string(event);
    std::string result;

    if (event == 0) {
        return "Slave Initiated Communication Restart: " + event_string;
    } else if (event == 0x04) {
        return "Slave Entered Listen Only Mode: " + event_string;
    } else if ((event & 0x80) == 1) {
        return std::string("Slave Modbus Receive Event: ") + event_string[0]
            + " (Not Used), " + event_string[1] + " (Communications Error), "
            + event_string[2] + " (Not Used), " + event_string[3]
            + " (Not Used), " + event_string[4] + " (Character Overrun), "
            + event_string[5] + " (Currently in Listen Only Mode), "
            + event_string[6] + " (Broadcast Received), " + event_string[7];
    } else if ((event & 0x40) == 1) {
        return std::string("Slave Modbus Send Event: ") + event_string[0]
            + " (Read Exception Sent (Exception Codes 1-3)), " + event_string[1]
            + " (Slave Abort Exception Sent (Exception Code 4)), "
            + event_string[2]
            + " (Slave Busy Exception Sent (Exception Codes 5-6)), "
            + event_string[3]
            + " (Slave Program NAK Exception Sent (Exception Code 7)), "
            + event_string[4] + " (Write Timeout Error Occured), "
            + event_string[5] + " (Currently in Listen Only Mode), "
            + event_string[6] + ", " + event_string[7];
    } else {
        return "Invalid Event: " + event_string;
    }
}

std::string get_diagnostics_subfunction_string(uint16_t subfunction)
{
    switch (subfunction) {
    case DIAG_RET_QUERY_DATA:
        return "Read Query Data";
    case DIAG_RESTART_COMM_OPTION:
        return "Restart Communications Option";
    case DIAG_RET_DIAG_REG:
        return "Return Diagnostic Register";
    case DIAG_CHG_ASCII_DEL:
        return "Change ASCII Input Delimiter";
    case DIAG_FORCE_LISTEN_ONLY_MODE:
        return "Force Listen Only Mode";
    case DIAG_CLR_CTRS_DIAG_REGS:
        return "Clear Counters and Diagnostic Register";
    case DIAG_RET_BUS_MSG_COUNT:
        return "Return Bus Message Count";
    case DIAG_RET_BUS_COMM_ERR_COUNT:
        return "Return Bus Communication Error Count";
    case DIAG_RET_BUS_EXC_ERR_COUNT:
        return "Return Bus Exception Error Count";
    case DIAG_RET_SLAVE_MSG_COUNT:
        return "Return Slave Message Count";
    case DIAG_RET_SLAVE_NO_RESP_COUNT:
        return "Return Slave No Response Count";
    case DIAG_RET_SLAVE_NAK_COUNT:
        return "Return Slave NAK Count";
    case DIAG_RET_SLAVE_BUSY_COUNT:
        return "Return Slave Busy Count";
    case DIAG_RET_BUS_CHAR_OVERRUN_COUNT:
        return "Return Bus Character Overrun Count";
    case DIAG_RET_OVERRUN_ERR_COUNT:
        return "Return IOP Overrun Count";
    case DIAG_CLR_OVERRUN_COUNTER_FLAG:
        return "Clear Overrun Counter and Flag";
    case DIAG_MODBUS_PLUS_STATS:
        return "Get/Clear Modbus Plus Statistics";
    default:
        return "Unknown Subfunction";
    }
}

std::string get_exception_code_string(uint8_t exception_code)
{
    switch (exception_code) {
    case ILLEGAL_FUNCTION:
        return "Illegal Function";
    case ILLEGAL_DATA_ADDRESS:
        return "Illegal Data Address";
    case ILLEGAL_DATA_VALUE:
        return "Illegal Data Value";
    case SLAVE_DEVICE_FAILURE:
        return "Slave Device Failure";
    case ACKNOWLEDGE:
        return "Acknowledge";
    case SLAVE_DEVICE_BUSY:
        return "Slave Device Busy";
    case NEGATIVE_ACKNOWLEDGE:
        return "Negative Acknowledge";
    case MEMORY_PARITY_ERROR:
        return "Memory Parity Error";
    default:
        return "Unknown Exception Code";
    }
}

std::string get_exception_code_description(uint8_t exception_code)
{
    switch (exception_code) {
    case ILLEGAL_FUNCTION:
        return "The function code received in the query is not an allowable "
            "action for the slave. If a Poll Program Complete command was "
            "issued, this code indicates that no program function preceded it.";
    case ILLEGAL_DATA_ADDRESS:
        return "The data address received in the query is not an allowable "
            "address for the slave.";
    case ILLEGAL_DATA_VALUE:
        return "A value contained in the query data field is not an allowable "
            "value for theslave.";
    case SLAVE_DEVICE_FAILURE:
        return "An unrecoverable error occurred while the slave was attempting "
            "to perform the requested action.";
    case ACKNOWLEDGE:
        return "The slave has accepted the request and is processing it, but a "
            "long duration of time will be required to do so. This response is "
            "returned to prevent a timeout error from occurring in the master. "
            "The master can next issue a Poll Program Complete message to "
            "determine if processing is completed.";
    case SLAVE_DEVICE_BUSY:
        return "The slave is engaged in processing a long–duration program "
            "command. The master should retransmit the message later when the "
            "slave is free.";
    case NEGATIVE_ACKNOWLEDGE:
        return "The slave cannot perform the program function received in the "
            "query. This code is returned for an unsuccessful programming "
            "request using function code 13 or 14 decimal. The master should "
            "request diagnostic or error information from the slave.";
    case MEMORY_PARITY_ERROR:
        return "The slave attempted to read extended memory, but detected a "
            "parity error in the memory. The master can retry the request, but "
            "service may be required on the slave device.";
    default:
        return "No Exception Code Description";
    }
}

std::string get_function_code_string(uint8_t function_code)
{
    if (function_code > 0x80)
        return "EXCEPTION";

    switch (function_code) {
    case READ_COIL_STATUS:
        return "READ COIL STATUS";
    case READ_INPUT_STATUS:
        return "READ INPUT STATUS";
    case READ_HOLDING_REGISTERS:
        return "READ HOLDING REGISTERS";
    case READ_INPUT_REGISTERS:
        return "READ INPUT REGISTERS";
    case FORCE_SINGLE_COIL:
        return "FORCE SINGLE COIL";
    case PRESET_SINGLE_REGISTER:
        return "PRESET SINGLE REGISTER";
    case READ_EXCEPTION_STATUS:
        return "READ EXCEPTION STATUS";
    case DIAGNOSTICS:
        return "DIAGNOSTICS";
    case FETCH_COMM_EVENT_COUNTER:
        return "FETCH COMMUNICATION EVENT COUNTER";
    case FETCH_COMM_EVENT_LOG:
        return "FETCH COMMUNICATION EVENT LOG";
    case FORCE_MULTIPLE_COILS:
        return "FORCE MULTIPLE COILS";
    case PRESET_MULTIPLE_REGISTERS:
        return "PRESET MULTIPLE REGISTERS";
    case REPORT_SLAVE_ID:
        return "REPORT SLAVE ID";
    default:
        return "UNKNOWN";
    }
}

std::string get_modbus_tcp_generic_string(const struct modbus_tcp_generic
                                          *modbus_struct, char separator)
{
    return "transaction id: " +  std::to_string(modbus_struct->transaction_id)
        + separator + "protocol id: "
        + std::to_string(modbus_struct->protocol_id)
        + separator + "length: " + std::to_string(modbus_struct->length)
        + separator + "slave id: " + std::to_string(modbus_struct->unit_id)
        + separator + "function code: "
        + std::to_string(modbus_struct->function_code);
}

std::string get_modbus_read_query_string(const struct modbus_read_query
                                         *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "starting address: "
        + std::to_string(modbus_struct->starting_address) + separator
        + "number of points: " + std::to_string(modbus_struct->num_of_points);
}

std::string get_modbus_read_response_string(const struct modbus_read_response
                                            *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "byte count: "
        + std::to_string(modbus_struct->byte_count);
}

std::string get_modbus_single_write_string(const struct modbus_single_write
                                           *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "address: "
        + std::to_string(modbus_struct->address);
}

std::string get_modbus_exception_status_response_string(
    const struct modbus_exception_status_response *modbus_struct,
    char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "coil data: "
        + std::to_string(modbus_struct->coil_data);
}

std::string get_modbus_diagnostics_string(const struct modbus_diagnostics
    *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "subfunction: "
        + std::to_string(modbus_struct->subfunction) + " ("
        + get_diagnostics_subfunction_string(modbus_struct->subfunction) + ")"
        + separator + "data: " + std::to_string(modbus_struct->data);
}

std::string get_modbus_event_counter_response_string(
    const struct modbus_event_counter_response *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "status: "
        + std::to_string(modbus_struct->status) + separator + "event count: "
        + std::to_string(modbus_struct->event_count);
}

std::string get_modbus_event_log_response_string(
    const struct modbus_event_log_response *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "status: "
        + std::to_string(modbus_struct->status) + separator + "event count: "
        + std::to_string(modbus_struct->event_count) + separator
        + "message count: " + std::to_string(modbus_struct->message_count)
        + separator + "event 0: "
        + get_event_log_event_string(modbus_struct->event0) + separator
        + "event 1: " + get_event_log_event_string(modbus_struct->event1);
}

std::string get_modbus_multiple_write_query_string(
    const struct modbus_multiple_write_query *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "starting address: "
        + std::to_string(modbus_struct->starting_address)
        + separator + "number of points: "
        + std::to_string(modbus_struct->num_of_points)
        + separator + "byte count: "
        + std::to_string(modbus_struct->byte_count);
}

std::string get_modbus_multiple_write_response_string(
    const struct modbus_multiple_write_response *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "starting address: "
        + std::to_string(modbus_struct->starting_address)
        + separator + "number of points: "
        + std::to_string(modbus_struct->num_of_points);
}

std::string get_modbus_report_slave_id_response_string(
    const struct modbus_report_slave_id_response *modbus_struct,
    char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "byte count: "
        + std::to_string(modbus_struct->byte_count)
        + separator + "slave ID: " + std::to_string(modbus_struct->slave_id)
        + separator + "run indicator status: "
        + std::to_string(modbus_struct->run_indicator_status);
}

std::string get_modbus_mask_write_string(const struct modbus_mask_write
    *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "address: "
        + std::to_string(modbus_struct->address) + separator + "and mask: "
        + byte_to_binary_string(modbus_struct->and_mask) + separator
        + "or mask: " + byte_to_binary_string(modbus_struct->or_mask);
}

std::string get_modbus_exception_string(const struct modbus_exception
    *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "exception code: "
        + get_exception_code_string(modbus_struct->exception_code) + separator
        + "description: "
        + get_exception_code_description(modbus_struct->exception_code);
}

void display_modbus_tcp_generic(const struct modbus_tcp_generic *modbus_struct,
                                bool query_packet)
{
    std::cout << "MODBUS " << (query_packet ? "query" : "response")
        << std::endl;
    std::cout << get_function_code_string(modbus_struct->function_code)
        << std::endl;
    std::cout << "transaction id: " << modbus_struct->transaction_id
        << std::endl;
    std::cout << "protocol id: " << modbus_struct->protocol_id << std::endl;
    std::cout << "length: " << modbus_struct->length << std::endl;
    std::cout << "slave id: " << unsigned(modbus_struct->unit_id) << std::endl;
    std::cout << "function code: " << unsigned(modbus_struct->function_code)
        << std::endl;
}

void display_modbus_read_query(const struct modbus_read_query *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), true);

    std::cout << "starting address: " << modbus_struct->starting_address
        << std::endl;
    std::cout << "num of points: " << modbus_struct->num_of_points << std::endl;
}

void display_modbus_read_response(const struct modbus_read_response
                                  *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "byte count: " << unsigned(modbus_struct->byte_count)
        << std::endl;
}

void display_modbus_single_write(const struct modbus_single_write
                                 *modbus_struct, bool query_packet)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), query_packet);

    std::cout << "address: " << modbus_struct->address << std::endl;
    std::cout << "value: " << modbus_struct->value << std::endl;
}

void display_modbus_exception_status_response(
    const struct modbus_exception_status_response *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "coils data: "
        << byte_to_binary_string(modbus_struct->coil_data) << std::endl;
}

void display_modbus_diagnostics(const struct modbus_diagnostics *modbus_struct,
                                bool query_packet)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), query_packet);

    std::cout << "subfunction: "
        << get_diagnostics_subfunction_string(modbus_struct->subfunction)
        << std::endl;

    std::cout << "data: " << modbus_struct->data << std::endl;
}

void display_modbus_event_counter_response(
    const struct modbus_event_counter_response *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "status: " << modbus_struct->status << std::endl;
    std::cout << "event count: " << modbus_struct->event_count << std::endl;
}

void display_modbus_event_log_response(const struct modbus_event_log_response
                                       *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "status: " << modbus_struct->status << std::endl;
    std::cout << "event count: " << modbus_struct->event_count << std::endl;
    std::cout << "message count: " << modbus_struct->message_count << std::endl;
    std::cout << "event 0: "
        << get_event_log_event_string(modbus_struct->event0) << std::endl;
    std::cout << "event 1: "
        << get_event_log_event_string(modbus_struct->event1) << std::endl;
}

void display_modbus_multiple_write_query(
    const struct modbus_multiple_write_query *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), true);

    std::cout << "starting address: " << modbus_struct->starting_address
        << std::endl;
    std::cout << "num of points: " << modbus_struct->num_of_points << std::endl;
    std::cout << "byte count: " << unsigned(modbus_struct->byte_count)
        << std::endl;
}

void display_modbus_multiple_write_response(
    const struct modbus_multiple_write_response *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "starting address: " << modbus_struct->starting_address
        << std::endl;
    std::cout << "num of points: " << modbus_struct->num_of_points << std::endl;
}

void display_modbus_report_slave_id_response(
    const struct modbus_report_slave_id_response *modbus_struct)
{
    uint8_t byte_count;

    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "byte count: " << unsigned(modbus_struct->byte_count)
        << std::endl;
    std::cout << "slave id: " << unsigned(modbus_struct->slave_id) << std::endl;
    std::cout << "run indicator status: "
        << unsigned(modbus_struct->run_indicator_status) << std::endl;
    std::cout << "additional data: " << std::endl;

    byte_count = modbus_struct->byte_count - 2;

    for (uint8_t i = 0; i < byte_count; i++)
        std::cout << modbus_struct->additional_data[i] << ", ";

    std::cout << std::endl; 
}

void display_modbus_mask_write(const struct modbus_mask_write *modbus_struct,
                               bool query_packet)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), query_packet);

    std::cout << "address: " << modbus_struct->address << std::endl;
    std::cout << "and mask: " << byte_to_binary_string(modbus_struct->and_mask)
        << std::endl;
    std::cout << "or mask: " << byte_to_binary_string(modbus_struct->or_mask)
        << std::endl;
}

void display_modbus_exception(const struct modbus_exception *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "exception code: "
        << get_exception_code_string(modbus_struct->exception_code)
        << std::endl;

    std::cout << "description: "
        << get_exception_code_description(modbus_struct->exception_code)
        << std::endl;
}
