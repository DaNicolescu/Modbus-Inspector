#include <string.h>
#include <iostream>

#include "device_struct.h"

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
    address += 1;
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
    address += 10001;
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
    address += 40001;
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
    address += 40001;
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
    address += 30001;
    uint16_t last_address = address + num_of_points - 1;

    for (const std::pair<uint16_t, uint16_t> &pair : this->input_registers) {
        if (pair.first <= address && pair.second >= last_address)
            return true;
    }

    return false;
}
