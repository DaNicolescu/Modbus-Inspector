#include <iostream>
#include <string.h>
#include <netinet/in.h>

#include "modbus.h"

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
                                          *modbus_struct)
{
    return "transaction id: " +  std::to_string(modbus_struct->transaction_id)
        + ", protocol id: " + std::to_string(modbus_struct->protocol_id)
        + ", length: " + std::to_string(modbus_struct->length)
        + ", slave id: " + std::to_string(modbus_struct->unit_id)
        + ", function code: " + std::to_string(modbus_struct->function_code);
}

std::string get_modbus_read_query_string(const struct modbus_read_query
                                         *modbus_struct)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header))
        + ", starting address: " +  std::to_string(
            modbus_struct->starting_address)
        + ", number of points: " + std::to_string(modbus_struct->num_of_points);
}

std::string get_modbus_read_response_string(const struct modbus_read_response
                                            *modbus_struct)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header))
        + ", byte count: " +  std::to_string(modbus_struct->byte_count);
}

std::string get_modbus_single_write_string(const struct modbus_single_write
                                           *modbus_struct)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header))
        + ", address: " +  std::to_string(modbus_struct->address);
}

std::string get_modbus_multiple_write_query_string(
    const struct modbus_multiple_write_query *modbus_struct)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header))
        + ", starting address: "
        + std::to_string(modbus_struct->starting_address)
        + ", number of points: "
        + std::to_string(modbus_struct->num_of_points)
        + ", byte count: " + std::to_string(modbus_struct->byte_count);
}

std::string get_modbus_multiple_write_response_string(
    const struct modbus_multiple_write_response *modbus_struct)
{
    return get_modbus_tcp_generic_string(&(modbus_struct->generic_header))
        + ", starting address: "
        + std::to_string(modbus_struct->starting_address)
        + ", number of points: "
        + std::to_string(modbus_struct->num_of_points);
}
