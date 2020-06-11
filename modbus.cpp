#include <iostream>
#include <string.h>
#include <netinet/in.h>

#include "modbus.h"

struct modbus_read_query *get_modbus_read_query(const uint8_t *payload)
{
    struct modbus_read_query *modbus_struct;

    modbus_struct = new modbus_read_query;

    memcpy(modbus_struct, payload, sizeof(struct modbus_read_query));

    modbus_struct->starting_address = htons(modbus_struct->starting_address);
    modbus_struct->num_of_points = htons(modbus_struct->num_of_points);

    return modbus_struct;
}

struct modbus_read_response *get_modbus_read_response(const uint8_t *payload)
{
    struct modbus_read_response *modbus_struct;

    modbus_struct = new modbus_read_response;

    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic) + 1);

    modbus_struct->data = (uint8_t*) malloc(modbus_struct->byte_count);

    if (!modbus_struct->data) {
        std::cout << "Failed to allocate memory" << std::endl;

        return NULL;
    }

    memcpy(modbus_struct->data, payload + sizeof(struct modbus_tcp_generic) + 1,
           modbus_struct->byte_count);

    return modbus_struct;
}

void get_modbus_single_write(struct modbus_single_write *modbus_struct,
                             const uint8_t *payload)
{
    memcpy(modbus_struct, payload, sizeof(struct modbus_single_write));

    modbus_struct->address = htons(modbus_struct->address);
    modbus_struct->value = htons(modbus_struct->value);
}

void get_modbus_multiple_write_query(
    struct modbus_multiple_write_query *modbus_struct, const uint8_t *payload)
{
    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic) + 5);

    modbus_struct->starting_address = htons(modbus_struct->starting_address);
    modbus_struct->num_of_points = htons(modbus_struct->num_of_points);

    modbus_struct->data = (uint8_t*) malloc(modbus_struct->byte_count);

    if (!modbus_struct->data) {
        std::cout << "Failed to allocate memory" << std::endl;

        return;
    }

    memcpy(modbus_struct->data, payload + sizeof(struct modbus_tcp_generic) + 5,
           modbus_struct->byte_count);
}

void get_modbus_multiple_write_response(
    struct modbus_multiple_write_response *modbus_struct,
    const uint8_t *payload)
{
    memcpy(modbus_struct, payload, sizeof(struct modbus_tcp_generic) + 4);

    modbus_struct->starting_address = htons(modbus_struct->starting_address);
    modbus_struct->num_of_points = htons(modbus_struct->num_of_points);
}

