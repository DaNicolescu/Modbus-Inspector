#include <string.h>
#include <iostream>

#include "device_struct.h"
#include "modbus.h"
#include "utils.h"
#include "config.h"

bool device_struct::supported_function(uint8_t function)
{
    for (uint8_t crt_func : this->generic_supported_functions) {
        if (crt_func == function)
            return true;
    }

    for (uint8_t crt_func : this->specific_supported_functions) {
        if (crt_func == function)
            return true;
    }

    return false;
}

struct address_struct* device_struct::get_address(uint16_t address)
{
    std::unordered_map<uint16_t, struct address_struct*>::iterator it;

    it = this->addresses_map.find(address);

    if (it != this->addresses_map.end())
        return it->second;

    return NULL;
}

std::pair<uint16_t, uint16_t> device_struct::make_uint16_pair(std::string str)
{
    std::pair<uint16_t, uint16_t> pair;
    uint16_t first_num;
    uint16_t second_num;
    char *cstr = new char[str.length() + 1];
    char *token;

    strcpy(cstr, str.c_str());

    token = strtok(cstr, ":");

    sscanf(token, "%hu", &first_num);

    std::cout << "token1:" << token << std::endl;

    token = strtok(NULL, ":");

    if (!token) {
        pair.first = first_num;
        pair.second = first_num;
    } else {
        std::cout << "token2:" << token << std::endl;
        sscanf(token, "%hu", &second_num);

        pair.first = first_num;
        pair.second = second_num;
    }

    return pair;
}

void device_struct::add_read_coils_range(std::string str)
{
    this->read_coils.push_back(device_struct::make_uint16_pair(str));
}

void device_struct::add_write_coils_range(std::string str)
{
    this->write_coils.push_back(device_struct::make_uint16_pair(str));
}

void device_struct::add_inputs_range(std::string str)
{
    this->inputs.push_back(device_struct::make_uint16_pair(str));
}

void device_struct::add_read_hld_regs_range(std::string str)
{
    this->read_holding_registers.push_back(
        device_struct::make_uint16_pair(str));
}

void device_struct::add_write_hld_regs_range(std::string str)
{
    this->write_holding_registers.push_back(
        device_struct::make_uint16_pair(str));
}

void device_struct::add_input_regs_range(std::string str)
{
    this->input_registers.push_back(device_struct::make_uint16_pair(str));
}

void device_struct::display_addresses(uint16_t address, uint16_t num_of_points)
{
    std::unordered_map<uint16_t, struct address_struct*>::iterator it;
    uint16_t last_address = address + num_of_points - 1;

    std::cout << "Addresses: " << std::endl;

    for (; address <= last_address; address++) {
        it = this->addresses_map.find(address);
        std::cout << address << ": " << it->second->description << std::endl;
    }
}

void device_struct::display_addresses(struct modbus_aggregate *aggregated_frame)
{
    std::unordered_map<uint16_t, struct address_struct*>::iterator it;
    struct modbus_read_query *read_query;
    struct modbus_read_response *read_response;
    struct modbus_single_write *single_write_query;
    struct modbus_single_write *single_write_response;
    struct modbus_multiple_write_query *multiple_write_query;
    struct modbus_multiple_write_response *multiple_write_response;
    uint16_t address;
    uint16_t last_address;
    uint16_t num_of_points;
    std::string binary_string;
    uint8_t i;
    uint8_t data_index;

    switch (aggregated_frame->function_code) {
    case READ_COIL_STATUS:
        std::cout << "AGGREGATED READ COIL STATUS" << std::endl;

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        std::cout << "starting address: " << read_query->starting_address
            << std::endl;
        std::cout << "num of points: " << read_query->num_of_points
            << std::endl;

        address = read_query->starting_address + COILS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        i = 0;
        data_index = 0;
        binary_string = byte_to_binary_string(read_response->data[data_index]);

        for (; address <= last_address; address++) {
            if (i == 8) {
                i = 0;
                data_index++;
                binary_string = byte_to_binary_string(
                    read_response->data[data_index]);
            }

            it = this->addresses_map.find(address);
            std::cout << address << " (" << it->second->description
                << ") reading is " << binary_string[i] << std::endl;
            std::cout << "Notes: " << it->second->notes << std::endl;

            i++;
        }

        break;
    case READ_INPUT_STATUS:
        std::cout << "AGGREGATED READ INPUT STATUS" << std::endl;

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        std::cout << "starting address: " << read_query->starting_address
            << std::endl;
        std::cout << "num of points: " << read_query->num_of_points
            << std::endl;

        address = read_query->starting_address + INPUTS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        i = 0;
        data_index = 0;
        binary_string = byte_to_binary_string(read_response->data[data_index]);

        for (; address <= last_address; address++) {
            if (i == 8) {
                i = 0;
                data_index++;
                binary_string = byte_to_binary_string(
                    read_response->data[data_index]);
            }

            it = this->addresses_map.find(address);
            std::cout << address << " (" << it->second->description
                << ") reading is " << binary_string[i] << std::endl;
            std::cout << "notes: " << it->second->notes << std::endl;

            i++;
        }

        break;
    case READ_HOLDING_REGISTERS:
        std::cout << "AGGREGATED READ HOLDING REGISTERS" << std::endl;

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        std::cout << "starting address: " << read_query->starting_address
            << std::endl;
        std::cout << "num of points: " << read_query->num_of_points
            << std::endl;

        address = read_query->starting_address + HLD_REGS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        data_index = 0;

        for (; address <= last_address; address++) {

            it = this->addresses_map.find(address);
            std::cout << address << " (" << it->second->description
                << ") reading is ";
           
            if (it->second->type == XLS_FLOAT_TYPE) {
                std::cout << bytes_to_float(read_response->data[data_index],
                                            read_response->data[data_index + 1]);
            } else {
                std::cout << bytes_to_int(read_response->data[data_index],
                                          read_response->data[data_index + 1]);
            }

            std::cout << std::endl;
            std::cout << "notes: " << it->second->notes << std::endl;

            data_index += 2;
        }

        break;
    case READ_INPUT_REGISTERS:
        std::cout << "AGGREGATED READ INPUT REGISTERS" << std::endl;

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        std::cout << "starting address: " << read_query->starting_address
            << std::endl;
        std::cout << "num of points: " << read_query->num_of_points
            << std::endl;

        address = read_query->starting_address + INPUT_REGS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        data_index = 0;

        for (; address <= last_address; address++) {

            it = this->addresses_map.find(address);
            std::cout << address << " (" << it->second->description
                << ") reading is ";
           
            if (it->second->type == XLS_FLOAT_TYPE) {
                std::cout << bytes_to_float(read_response->data[data_index],
                                            read_response->data[data_index + 1]);
            } else {
                std::cout << bytes_to_int(read_response->data[data_index],
                                          read_response->data[data_index + 1]);
            }

            std::cout << std::endl;
            std::cout << "notes: " << it->second->notes << std::endl;

            data_index += 2;
        }

        break;
    case FORCE_SINGLE_COIL:
        std::cout << "AGGREGATED FORCE SINGLE COIL" << std::endl;

        single_write_query = (struct modbus_single_write*)
            aggregated_frame->query;
        single_write_response = (struct modbus_single_write*)
            aggregated_frame->response;

        address = single_write_query->address + COILS_OFFSET;

        it = this->addresses_map.find(address);

        std::cout << address << " (" << it->second->description
            << ") was set to " << unsigned(single_write_query->value)
            << std::endl;

        std::cout << "notes: " << it->second->notes << std::endl;

        break;
    case PRESET_SINGLE_REGISTER:
        std::cout << "AGGREGATED PRESET SINGLE REGISTER" << std::endl;

        single_write_query = (struct modbus_single_write*)
            aggregated_frame->query;
        single_write_response = (struct modbus_single_write*)
            aggregated_frame->response;

        address = single_write_query->address + HLD_REGS_OFFSET;

        it = this->addresses_map.find(address);

        std::cout << address << " (" << it->second->description
            << ") was set to ";

        if (it->second->type == XLS_FLOAT_TYPE) {
            std::cout << float(single_write_query->value) << std::endl;
        } else {
            std::cout << single_write_query->value << std::endl;
        }

        std::cout << "notes: " << it->second->notes << std::endl;

        break;
    case READ_EXCEPTION_STATUS:
        break;
    case FORCE_MULTIPLE_COILS:
        std::cout << "AGGREGATED FORCE MULTIPLE COILS" << std::endl;

        multiple_write_query = (struct modbus_multiple_write_query*)
            aggregated_frame->query;
        multiple_write_response = (struct modbus_multiple_write_response*)
            aggregated_frame->response;

        std::cout << "starting address: "
            << multiple_write_query->starting_address << std::endl;
        std::cout << "num of points: "
            << multiple_write_query->num_of_points << std::endl;
        std::cout << "byte count: "
            << unsigned(multiple_write_query->byte_count) << std::endl;

        address = multiple_write_query->starting_address + COILS_OFFSET;
        last_address = address + multiple_write_query->num_of_points - 1;

        i = 0;
        data_index = 0;
        binary_string = byte_to_binary_string(
            multiple_write_query->data[data_index]);

        for (; address <= last_address; address++) {
            if (i == 8) {
                i = 0;
                data_index++;
                binary_string = byte_to_binary_string(
                    multiple_write_query->data[data_index]);
            }

            it = this->addresses_map.find(address);
            std::cout << address << " (" << it->second->description
                << ") was set to " << binary_string[i] << std::endl;
            std::cout << "Notes: " << it->second->notes << std::endl;

            i++;
        }
        
        break;
    case PRESET_MULTIPLE_REGISTERS:
        std::cout << "AGGREGATED PRESET MULTIPLE REGISTERS" << std::endl;

        multiple_write_query = (struct modbus_multiple_write_query*)
            aggregated_frame->query;
        multiple_write_response = (struct modbus_multiple_write_response*)
            aggregated_frame->response;

        std::cout << "starting address: "
            << multiple_write_query->starting_address << std::endl;
        std::cout << "num of points: "
            << multiple_write_query->num_of_points << std::endl;
        std::cout << "byte count: "
            << unsigned(multiple_write_query->byte_count) << std::endl;

        address = multiple_write_query->starting_address + HLD_REGS_OFFSET;
        last_address = address + multiple_write_query->num_of_points - 1;

        data_index = 0;

        for (; address <= last_address; address++) {

            it = this->addresses_map.find(address);
            std::cout << address << " (" << it->second->description
                << ") was set to ";
           
            if (it->second->type == XLS_FLOAT_TYPE) {
                std::cout << bytes_to_float(
                    multiple_write_query->data[data_index],
                    multiple_write_query->data[data_index + 1]);
            } else {
                std::cout << bytes_to_int(
                    multiple_write_query->data[data_index],
                    multiple_write_query->data[data_index + 1]);
            }

            std::cout << std::endl;
            std::cout << "notes: " << it->second->notes << std::endl;

            data_index += 2;
        }

        break;
    case REPORT_SLAVE_ID:
        break;
    default:
        std::cout << "Function code decoding not yet implemented" << std::endl;
    }
}

bool device_struct::valid_read_coils_addresses(uint16_t address,
                                               uint16_t num_of_points)
{
    address += 1;
    uint16_t last_address = address + num_of_points - 1;

    for (const std::pair<uint16_t, uint16_t> &pair : this->read_coils) {
        if (pair.first <= address && pair.second >= last_address)
            return true;
    }

    return false;
}

bool device_struct::valid_write_coils_addresses(uint16_t address,
                                                uint16_t num_of_points)
{
    address += COILS_OFFSET;
    uint16_t last_address = address + num_of_points - 1;

    for (const std::pair<uint16_t, uint16_t> &pair : this->write_coils) {
        if (pair.first <= address && pair.second >= last_address)
            return true;
    }

    return false;
}

bool device_struct::valid_inputs_addresses(uint16_t address,
                                           uint16_t num_of_points)
{
    address += INPUTS_OFFSET;
    uint16_t last_address = address + num_of_points - 1;

    for (const std::pair<uint16_t, uint16_t> &pair : this->inputs) {
        if (pair.first <= address && pair.second >= last_address)
            return true;
    }

    return false;
}

bool device_struct::valid_read_hld_regs_addresses(uint16_t address,
                                                  uint16_t num_of_points)
{
    address += HLD_REGS_OFFSET;
    uint16_t last_address = address + num_of_points - 1;

    for (const std::pair<uint16_t, uint16_t> &pair
         : this->read_holding_registers) {
        if (pair.first <= address && pair.second >= last_address)
            return true;
    }

    return false;
}

bool device_struct::valid_write_hld_regs_addresses(uint16_t address,
                                                   uint16_t num_of_points)
{
    address += HLD_REGS_OFFSET;
    uint16_t last_address = address + num_of_points - 1;

    for (const std::pair<uint16_t, uint16_t> &pair
         : this->write_holding_registers) {
        if (pair.first <= address && pair.second >= last_address)
            return true;
    }

    return false;
}

bool device_struct::valid_input_regs_addresses(uint16_t address,
                                               uint16_t num_of_points)
{
    address += INPUT_REGS_OFFSET;
    uint16_t last_address = address + num_of_points - 1;

    for (const std::pair<uint16_t, uint16_t> &pair : this->input_registers) {
        if (pair.first <= address && pair.second >= last_address)
            return true;
    }

    return false;
}
