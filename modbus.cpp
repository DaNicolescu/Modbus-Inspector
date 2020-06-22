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

struct modbus_exception_response *get_modbus_exception_response(
    const uint8_t *payload)
{
    struct modbus_exception_response *modbus_struct;

    modbus_struct = new modbus_exception_response;

    reorder_modbus_tcp_generic_bytes(&(modbus_struct->generic_header));

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

    return modbus_struct;
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

std::string get_modbus_exception_response_string(
    const struct modbus_exception_response *modbus_struct, char separator)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header),
        separator) + separator + "coil data: "
        + std::to_string(modbus_struct->coil_data);
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

void display_modbus_tcp_generic(const struct modbus_tcp_generic *modbus_struct,
                                bool query_packet)
{
    std::cout << "MODBUS " << (query_packet ? "query" : "response")
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

void display_modbus_exception_response(const struct modbus_exception_response
                                       *modbus_struct)
{
    display_modbus_tcp_generic(&(modbus_struct->generic_header), false);

    std::cout << "coils data: "
        << byte_to_binary_string(modbus_struct->coil_data) << std::endl;
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
    std::cout << "event 0: " << modbus_struct->event0 << std::endl;
    std::cout << "event 1: " << modbus_struct->event1 << std::endl;
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
