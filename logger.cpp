/* Compile with: g++ logger.c -lpcap */
#include <iostream>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sstream>
#include <algorithm>
#include <unordered_set>

#include "logger.h"
#include "XlsReader.h"

std::unordered_set<uint16_t> modbus_queries;
std::unordered_map<uint8_t, struct device_struct*> devices_map;

void list_devs()
{
    pcap_if_t *all_devs;
    pcap_if_t *current_dev;
    char error_buff[PCAP_ERRBUF_SIZE];
    int ret;

    ret = pcap_findalldevs(&all_devs, error_buff);

    if (ret) {
        std::cout << "pcap_findalldevs failes: " << error_buff << std::endl;

        return;
    }

    current_dev = all_devs;

    while (current_dev) {
        std::cout << current_dev->name << " " << (current_dev->description
            ? current_dev->description : "(no description)") << std::endl;

        current_dev = current_dev->next;
    }

    if (all_devs)
        pcap_freealldevs(all_devs);
}

bool modbus_packet_is_query(uint16_t transaction_id)
{
    if (modbus_queries.find(transaction_id) == modbus_queries.end())
        return true;

    return false;
}

void get_modbus_read_query(struct modbus_read_query *modbus_struct,
                           const uint8_t *payload)
{
    memcpy(modbus_struct, payload, sizeof(struct modbus_read_query));

    modbus_struct->starting_address = htons(modbus_struct->starting_address);
    modbus_struct->num_of_points = htons(modbus_struct->num_of_points);
}

void get_modbus_read_response(struct modbus_read_response *modbus_struct,
                              const uint8_t *payload)
{
    memcpy(modbus_struct, payload,
           sizeof(struct modbus_tcp_generic) + 1);

    modbus_struct->data = (uint8_t*) malloc(modbus_struct->byte_count);

    if (!modbus_struct->data) {
        std::cout << "Failed to allocate memory" << std::endl;

        return;
    }

    memcpy(modbus_struct->data, payload + sizeof(struct modbus_tcp_generic) + 1,
           modbus_struct->byte_count);
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

std::string byte_to_binary_string(uint8_t number)
{
    std::string binary_string;

    for (uint8_t i = 0; i < 8; i++) {
        if ((number >> (7 - i)) & 1)
            binary_string.push_back('1');
        else
            binary_string.push_back('0');
    }

    return binary_string;
}

struct device_struct *get_device(uint8_t slave_id)
{
    std::unordered_map<uint8_t, struct device_struct*>::iterator it;

    it = devices_map.find(slave_id);

    if (it != devices_map.end())
        return it->second;

    return NULL;
}

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

void my_packet_handler(uint8_t *args, const struct pcap_pkthdr *header,
                       const uint8_t *packet)
{
    struct ether_header *ethernet_header;
    struct modbus_tcp_generic *modbus;
    struct modbus_read_query read_query;
    struct modbus_read_response read_response;
    struct modbus_single_write single_write_packet;
    struct modbus_multiple_write_query multiple_write_query;
    struct modbus_multiple_write_response multiple_write_response;
    struct device_struct *dev;
    struct address_struct *addr;
    const uint8_t *ip_header;
    const uint8_t *tcp_header;
    const uint8_t *payload;
    int ethernet_header_length = ETH_HDR_LEN;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    bool query_packet;

    // std::cout << "entered handler" << std::endl;

    ethernet_header = (struct ether_header*) packet;

    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP) {
        std::cout << "Not an IP packet" << std::endl << std::endl;

        return;
    }

    // std::cout << "Total packet available: " << header->caplen << " bytes" <<
    // std::endl;

    // std::cout << "Expected packet size: " << header->len << " bytes" <<
    // std::endl;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F) * 4;

    // std::cout << "IP header length (IHL) in bytes: " << ip_header_length <<
    // std::endl;

    uint8_t protocol = *(ip_header + 9);

    if (protocol != IPPROTO_TCP) {
        std::cout << "Not a TCP packet" << std::endl << std::endl;

        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;

    // std::cout << "TCP header length in bytes: " << tcp_header_length <<
    // std::endl;

    int total_headers_size = ethernet_header_length
        + ip_header_length+tcp_header_length;

    // std::cout << "Size of all headers combined: " << total_headers_size <<
    // " bytes" << std::endl;

    payload_length = header->caplen
        - (ethernet_header_length + ip_header_length + tcp_header_length);

    // std::cout << "Payload size: " << payload_length << " bytes" << std::endl;

    payload = packet + total_headers_size;

    if (payload_length <= 0) {
        std::cout << "No modbus payload" << std::endl << std::endl;

        return;
    }

    modbus = (struct modbus_tcp_generic*) payload;

    query_packet = modbus_packet_is_query(htons(modbus->transaction_id));

    if (query_packet)
        modbus_queries.insert(htons(modbus->transaction_id));
    else
        modbus_queries.erase(htons(modbus->transaction_id));

    std::cout << "MODBUS " << (query_packet ? "query" : "response")
        << std::endl;
    std::cout << "transaction id: " << htons(modbus->transaction_id)
        << std::endl;
    std::cout << "protocol id: " << htons(modbus->protocol_id) << std::endl;
    std::cout << "length: " << htons(modbus->length) << std::endl;
    std::cout << "slave id: " << unsigned(modbus->unit_id) << std::endl;
    std::cout << "function code: " << unsigned(modbus->function_code)
        << std::endl;

    dev = get_device(modbus->unit_id);

    if (!dev) {
        std::cout << "The device with slave id " << unsigned(modbus->unit_id)
            << " does not exist" << std::endl;

        std::cout << std::endl;

        return;
    }

    if (!dev->supported_function(modbus->function_code)) {
        std::cout << "Function code " << unsigned(modbus->function_code)
            << " not supported" << std::endl;

        std::cout << std::endl;

        return;
    }

    switch (modbus->function_code) {
    case READ_COIL_STATUS:
        std::cout << "READ COIL STATUS" << std::endl;

        if (query_packet) {
            get_modbus_read_query(&read_query, payload);

            std::cout << "starting address: " << read_query.starting_address
                << std::endl;
            std::cout << "num of points: " << read_query.num_of_points
                << std::endl;

            if (!dev->valid_read_coils_addresses(read_query.starting_address,
                                                 read_query.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(read_query.starting_address,
                                   read_query.num_of_points);

        } else {
            get_modbus_read_response(&read_response, payload);

            std::cout << "byte count: " << unsigned(read_response.byte_count)
                << std::endl;

            for (uint8_t i = 0; i < read_response.byte_count; i++) {
                std::cout << unsigned(i) << ": "
                    << byte_to_binary_string(read_response.data[i])
                    << std::endl;
            }
        }

        break;
    case READ_INPUT_STATUS:
        std::cout << "READ INPUT STATUS" << std::endl;

        if (query_packet) {
            get_modbus_read_query(&read_query, payload);

            std::cout << "starting address: " << read_query.starting_address
                << std::endl;
            std::cout << "num of points: " << read_query.num_of_points
                << std::endl;

            if (!dev->valid_inputs_addresses(read_query.starting_address,
                                             read_query.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(read_query.starting_address,
                                   read_query.num_of_points);
        } else {
            get_modbus_read_response(&read_response, payload);

            std::cout << "byte count: " << unsigned(read_response.byte_count)
                << std::endl;

            for (uint8_t i = 0; i < read_response.byte_count; i++) {
                std::cout << unsigned(i) << ": "
                    << byte_to_binary_string(read_response.data[i])
                    << std::endl;
            }
        }

        break;
    case READ_HOLDING_REGISTERS:
        std::cout << "READ HOLDING REGISTERS" << std::endl;

        if (query_packet) {
            get_modbus_read_query(&read_query, payload);

            std::cout << "starting address: " << read_query.starting_address
                << std::endl;
            std::cout << "num of points: " << read_query.num_of_points
                << std::endl;

            if (!dev->valid_read_hld_regs_addresses(read_query.starting_address,
                                                    read_query.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(read_query.starting_address,
                                   read_query.num_of_points);
        } else {
            get_modbus_read_response(&read_response, payload);

            std::cout << "byte count: " << unsigned(read_response.byte_count)
                << std::endl;

            std::cout << "first byte of data: "
                << unsigned(read_response.data[0]) << std::endl;
        }

        break;
    case READ_INPUT_REGISTERS:
        std::cout << "READ INPUT REGISTERS" << std::endl;

        if (query_packet) {
            get_modbus_read_query(&read_query, payload);

            std::cout << "starting address: " << read_query.starting_address
                << std::endl;
            std::cout << "num of points: " << read_query.num_of_points
                << std::endl;

            if (!dev->valid_input_regs_addresses(read_query.starting_address,
                                                 read_query.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(read_query.starting_address,
                                   read_query.num_of_points);
        } else {
            get_modbus_read_response(&read_response, payload);

            std::cout << "byte count: " << unsigned(read_response.byte_count)
                << std::endl;

            std::cout << "first byte of data: "
                << unsigned(read_response.data[0]) << std::endl;
        }

        break;
    case FORCE_SINGLE_COIL:
        std::cout << "FORCE SINGLE COIL" << std::endl;

        get_modbus_single_write(&single_write_packet, payload);

        std::cout << "address: " << single_write_packet.address << std::endl;
        std::cout << "value: " << single_write_packet.value << std::endl;

        if (!dev->valid_write_coils_addresses(single_write_packet.address, 1)) {
            std::cout << "No such address exists" << std::endl;
            std::cout << std::endl;

            return;
        }

        dev->display_addresses(single_write_packet.address, 1);

        break;
    case PRESET_SINGLE_REGISTER:
        std::cout << "PRESET SINGLE REGISTER" << std::endl;

        get_modbus_single_write(&single_write_packet, payload);

        std::cout << "address: " << single_write_packet.address << std::endl;
        std::cout << "value: " << single_write_packet.value << std::endl;

        if (!dev->valid_write_hld_regs_addresses(single_write_packet.address,
                                                 1)) {
            std::cout << "No such address exists" << std::endl;
            std::cout << std::endl;

            return;
        }

        dev->display_addresses(single_write_packet.address, 1);

        break;
    case READ_EXCEPTION_STATUS:
        break;
    case FORCE_MULTIPLE_COILS:
        std::cout << "FORCE MULTIPLE COILS" << std::endl;

        if (query_packet) {
            get_modbus_multiple_write_query(&multiple_write_query, payload);

            std::cout << "starting address: "
                << multiple_write_query.starting_address << std::endl;
            std::cout << "num of points: "
                << multiple_write_query.num_of_points << std::endl;
            std::cout << "byte count: "
                << unsigned(multiple_write_query.byte_count) << std::endl;
            std::cout << "first byte of data: "
                << unsigned(multiple_write_query.data[0]) << std::endl;

            if (!dev->valid_write_coils_addresses(
                    multiple_write_query.starting_address,
                    multiple_write_query.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(multiple_write_query.starting_address,
                                   multiple_write_query.num_of_points);
        } else {
            get_modbus_multiple_write_response(&multiple_write_response,
                                               payload);

            std::cout << "starting address: "
                << multiple_write_response.starting_address << std::endl;
            std::cout << "num of points: "
                << multiple_write_response.num_of_points << std::endl;

            if (!dev->valid_write_coils_addresses(
                    multiple_write_response.starting_address,
                    multiple_write_response.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(multiple_write_response.starting_address,
                                   multiple_write_response.num_of_points);
        }

        break;
    case PRESET_MULTIPLE_REGISTERS:
        std::cout << "PRESET MULTIPLE REGISTERS" << std::endl;

        if (query_packet) {
            get_modbus_multiple_write_query(&multiple_write_query, payload);

            std::cout << "starting address: "
                << multiple_write_query.starting_address << std::endl;
            std::cout << "num of points: "
                << multiple_write_query.num_of_points << std::endl;
            std::cout << "byte count: "
                << unsigned(multiple_write_query.byte_count) << std::endl;
            std::cout << "first byte of data: "
                << unsigned(multiple_write_query.data[0]) << std::endl;

            if (!dev->valid_write_hld_regs_addresses(
                    multiple_write_query.starting_address,
                    multiple_write_query.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(multiple_write_query.starting_address,
                                   multiple_write_query.num_of_points);
        } else {
            get_modbus_multiple_write_response(&multiple_write_response,
                                               payload);

            std::cout << "starting address: "
                << multiple_write_response.starting_address << std::endl;
            std::cout << "num of points: "
                << multiple_write_response.num_of_points << std::endl;

            if (!dev->valid_write_hld_regs_addresses(
                    multiple_write_response.starting_address,
                    multiple_write_response.num_of_points)) {
                std::cout << "No such address exists" << std::endl;
                std::cout << std::endl;

                return;
            }

            dev->display_addresses(multiple_write_response.starting_address,
                                   multiple_write_response.num_of_points);
        }

        break;
    case REPORT_SLAVE_ID:
        break;
    default:
        std::cout << "Function code decoding not yet implemented" << std::endl;
    }

    std::cout << std::endl;
}

void read_range(struct address_struct *addr, std::string str)
{
    std::pair<union value_type, union value_type> pair;
    union value_type first_num;
    union value_type second_num;
    char *cstr = new char[str.length() + 1];
    char *token;

    strcpy(cstr, str.c_str());

    token = strtok(cstr, ":");

    std::cout << "read range: " << str << std::endl;

    if (!token) {
        std::cout << "Invalid Range" << std::endl;

        return;
    }

    switch (addr->type) {
    case XLS_INT_TYPE:
        sscanf(token, "%d", &first_num.i);

        break;
    case XLS_UINT_TYPE:
        sscanf(token, "%d", &first_num.i);

        break;
    case XLS_FLOAT_TYPE:
        sscanf(token, "%f", &first_num.f);

        break;
    default:
        std::cout << "Invalid Type" << std::endl;

        return;
    }

    std::cout << "token1:" << token << std::endl;

    token = strtok(NULL, ":");

    if (!token) {
        addr->possible_values.push_back(first_num);
    } else {
        std::cout << "token2:" << token << std::endl;
        switch (addr->type) {
        case XLS_INT_TYPE:
            sscanf(token, "%d", &second_num.i);

            break;
        case XLS_UINT_TYPE:
            sscanf(token, "%d", &second_num.i);

            break;
        case XLS_FLOAT_TYPE:
            sscanf(token, "%f", &second_num.f);

            break;
        default:
            std::cout << "Invalid Type" << std::endl;

            return;
        }

        pair.first = first_num;
        pair.second = second_num;

        addr->possible_ranges.push_back(pair);
    }

}

std::vector<std::string> split_into_strings(std::string str,
                                            std::string delimiter)
{
    std::cout << str << std::endl;
    std::string::iterator end_pos = std::remove(str.begin(), str.end(), ' ');
    str.erase(end_pos, str.end());
    std::cout << str << std::endl;
    char *cstr = new char[str.length() + 1];
    char *cdelimiter = new char[delimiter.length() + 1];
    char *current;
    std::vector<std::string> arr;

    std::cout << "Split into strings" << std::endl;

    strcpy(cstr, str.c_str());

    strcpy(cdelimiter, delimiter.c_str());

    std::cout << cstr << std::endl;
    std::cout << cdelimiter << std::endl;

    current = strtok(cstr, cdelimiter);

    while (current) {
        std::cout << current << std::endl;
        arr.push_back(current);
        current = strtok(NULL, cdelimiter);
    }

    return arr;
}

std::vector<uint8_t> split_into_uint8s(std::string str,
                                       std::string delimiter)
{
    char *cstr = const_cast<char*>(str.c_str());
    char *cdelimiter = const_cast<char*>(delimiter.c_str());
    char *current;
    int crt_num;
    std::vector<uint8_t> arr;

    current = strtok(cstr, cdelimiter);

    while (current) {
        std::stringstream sstream(current);
        sstream >> crt_num;
        arr.push_back(crt_num);
        current = strtok(NULL, cdelimiter);
    }

    return arr;
}

void display_xls_config_file(std::string file_name)
{
    xls::WorkBook work_book(file_name);
    int num_of_sheets = work_book.GetSheetCount();

    for (int sheet_num = 0; sheet_num < num_of_sheets; sheet_num++) {
        std::cout << "Sheet Name: " << work_book.GetSheetName(sheet_num)
            << std::endl;

        work_book.InitIterator(sheet_num);

        while (true) {
            xls::cellContent cell = work_book.GetNextCell();

            if (cell.type == xls::cellBlank)
                break;

            work_book.ShowCell(cell);
        }

        std::cout << std::endl << std::endl;
    }
}

void extract_data_from_xls_config_file(std::string file_name)
{
    xls::WorkBook work_book(file_name);
    int num_of_sheets = work_book.GetSheetCount();
    int devices_sheet_num;
    struct device_struct *dev = NULL;
    uint16_t crt_row = 0;
    int int_id;
    std::vector<std::string> coils_ranges;
    std::vector<std::string> strings_vec;

    for (devices_sheet_num = 0; devices_sheet_num < num_of_sheets;
         devices_sheet_num++) {

        if (work_book.GetSheetName(devices_sheet_num) == XLS_DEVICES_SHEET_NAME)
            break;
    }

    if (devices_sheet_num == num_of_sheets) {
        std::cout << "No sheet with the name " << XLS_DEVICES_SHEET_NAME
            << " found" << std::endl;

        return;
    }

    work_book.InitIterator(devices_sheet_num);

    std::cout << "pula1" << std::endl;

    while (true) {
        xls::cellContent cell = work_book.GetNextCell();

        if (cell.type == xls::cellBlank)
            break;

        work_book.ShowCell(cell);

        if (cell.row == 1)
            continue;

        switch (cell.col) {
        case XLS_DEVICES_SLAVE_ID_COLUMN:
            std::cout << "slave id" << std::endl;

            dev = new device_struct;

            std::cout << "malloced" << std::endl;

            if (!dev) {
                std::cout << "Not enough memory for a new device structure"
                    << std::endl;
            }

            sscanf(cell.str.c_str(), "%d", &int_id);

            dev->id = (uint8_t) int_id;
            std::cout << "dev id: " << (unsigned) dev->id << std::endl;
            dev->name = "No devices name";

            std::cout << "set device strings" << std::endl;

            devices_map[dev->id] = dev;

            crt_row = cell.row;

            break;
        case XLS_DEVICES_DEVICE_NAME_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            dev->name = cell.str;

            break;
        case XLS_DEVICES_READ_COILS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            coils_ranges = split_into_strings(cell.str, ",");

            for (std::string str : coils_ranges) {
                std::cout << "coil: " << str << std::endl;
                dev->add_read_coils_range(str);
            }

            break;
        case XLS_DEVICES_WRITE_COILS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            coils_ranges = split_into_strings(cell.str, ",");

            for (std::string str : coils_ranges) {
                std::cout << "coil: " << str << std::endl;
                dev->add_write_coils_range(str);
            }

            break;
        case XLS_DEVICES_INPUTS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "input: " << str << std::endl;
                dev->add_inputs_range(str);
            }

            break;
        case XLS_DEVICES_READ_HLD_REGS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "read holding register: " << str << std::endl;
                dev->add_read_hld_regs_range(str);
            }

            break;
        case XLS_DEVICES_WRITE_HLD_REGS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "write holding register: " << str << std::endl;
                dev->add_write_hld_regs_range(str);
            }

            break;
        case XLS_DEVICES_INPUT_REGS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

            strings_vec = split_into_strings(cell.str, ",");

            for (std::string str : strings_vec) {
                std::cout << "input register: " << str << std::endl;
                dev->add_input_regs_range(str);
            }

            break;
        case XLS_DEVICES_GENERIC_FUNCS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

           dev->generic_supported_functions = split_into_uint8s(cell.str, ",");

           break;
        case XLS_DEVICES_SPECIFIC_FUNCS_COLUMN:
            if (!dev || crt_row != cell.row) {
                std::cout << "No slave ID assigned" << std::endl;

                return;
            }

           dev->specific_supported_functions = split_into_uint8s(cell.str, ",");

            break;
         default:
            std::cout << "Invalid column" << std::endl;

            return;
        }
    }

    std::unordered_map<uint8_t, struct device_struct*>::iterator it;
    std::vector<std::string> range_strings;
    struct address_struct *addr;
    int device_sheet_num;
    int crt_dev_slave_id;

    for (it = devices_map.begin(); it != devices_map.end(); it++) {
        crt_dev_slave_id = it->first;
        dev = it->second;

        std::cout << "Device " << crt_dev_slave_id << std::endl;

        for (device_sheet_num = 0; device_sheet_num < num_of_sheets;
             device_sheet_num++) {

            if (work_book.GetSheetName(device_sheet_num)
                == XLS_DEVICE_ADDRESSES_SHEET_NAME
                + std::to_string(crt_dev_slave_id))
                break;
        }

        if (device_sheet_num == num_of_sheets) {
            std::cout << "No sheet found for device " << crt_dev_slave_id
                << std::endl;

            return;
        }

        work_book.InitIterator(device_sheet_num);

        while (true) {
            xls::cellContent cell = work_book.GetNextCell();

            if (cell.type == xls::cellBlank)
                break;

            work_book.ShowCell(cell);

            if (cell.row == 1)
                continue;

            switch (cell.col) {
            case XLS_DEVICE_ADDRESSES_ADDRESS_COLUMN:
                addr = new address_struct;

                if (!addr) {
                    std::cout << "Not enough memory to allocate an" <<
                        "address_struct" << std::endl;

                    return;
                }

                sscanf(cell.str.c_str(), "%hu", &addr->address);

                std::cout << "address: " << addr->address << std::endl;

                dev->addresses_map[addr->address] = addr;

                crt_row = cell.row;

                break;
            case XLS_DEVICE_ADDRESSES_RW_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                if (cell.str == XLS_ADDRESS_READ) {
                    addr->write = false;
                } else if (cell.str == XLS_ADDRESS_READ_WRITE) {
                    addr->write = true;
                } else {
                    std::cout << "Invalid R/W cell" << std::endl;

                    return;
                }

                break;
            case XLS_DEVICE_ADDRESSES_DESCRIPTION_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                addr->description = cell.str;

                break;
            case XLS_DEVICE_ADDRESSES_SIZE_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                if (cell.str == XLS_1BIT_ADDRESS_SIZE_STR) {
                    addr->size = XLS_1BIT_ADDRESS_SIZE;
                } else if (cell.str == XLS_8BIT_ADDRESS_SIZE_STR) {
                    addr->size = XLS_8BIT_ADDRESS_SIZE;
                } else if (cell.str == XLS_16BIT_ADDRESS_SIZE_STR) {
                    addr->size = XLS_16BIT_ADDRESS_SIZE;
                } else {
                    std::cout << "Invalid size" << std::endl;

                    return;
                }

                break;
            case XLS_DEVICE_ADDRESSES_TYPE_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                if (cell.str == XLS_BOOL_TYPE_STR) {
                    addr->type = XLS_BOOL_TYPE;
                } else if (cell.str == XLS_INT_TYPE_STR) {
                    addr->type = XLS_INT_TYPE;
                } else if (cell.str == XLS_UINT_TYPE_STR) {
                    addr->type = XLS_UINT_TYPE;
                } else if (cell.str == XLS_FLOAT_TYPE_STR) {
                    addr->type = XLS_FLOAT_TYPE;
                } else {
                    std::cout << "Invalid Type" << std::endl;

                    return;
                }

                break;
            case XLS_DEVICE_ADDRESSES_RANGE_COLUMN:
                if (!addr || crt_row != cell.row) {
                    std::cout << "No Address assigned" << std::endl;

                    return;
                }

                std::cout << std::endl;
                std::cout << std::endl;
                std::cout << std::endl;
                std::cout << std::endl;
                std::cout << std::endl;

                std::cout << cell.str << std::endl;

                range_strings = split_into_strings(cell.str, ",");

                for (std::string str : range_strings) {
                    std::cout << "read range for " << str << std::endl;
                    read_range(addr, str);
                }

                break;
            default:
                std::cout << "Invalid column" << std::endl;

                return;
            }
        }
    }

}

void display_devices()
{
    std::unordered_map<uint8_t, struct device_struct*>::iterator it;
    std::unordered_map<uint16_t, struct address_struct*>::iterator addresses_it;

    for (it = devices_map.begin(); it != devices_map.end(); it++) {
        std::cout << "Slave ID: " << unsigned(it->second->id) << std::endl;
        std::cout << "Name: " << it->second->name << std::endl;
        std::cout << "Read Coils: " << std::endl;

        for (std::pair<uint16_t, uint16_t> pair : it->second->read_coils) {
            std::cout << pair.first << ":" << pair.second << std::endl;
        }

        std::cout << "Write Coils: " << std::endl;

        for (std::pair<uint16_t, uint16_t> pair : it->second->write_coils) {
            std::cout << pair.first << ":" << pair.second << std::endl;
        }

        std::cout << "Inputs: " << std::endl;

        for (std::pair<uint16_t, uint16_t> pair : it->second->inputs) {
            std::cout << pair.first << ":" << pair.second << std::endl;
        }

        std::cout << "Read Holding Registers: " << std::endl;

        for (std::pair<uint16_t, uint16_t> pair
             : it->second->read_holding_registers) {
            std::cout << pair.first << ":" << pair.second << std::endl;
        }

        std::cout << "Write Holding Registers: " << std::endl;

        for (std::pair<uint16_t, uint16_t> pair
             : it->second->write_holding_registers) {
            std::cout << pair.first << ":" << pair.second << std::endl;
        }

        std::cout << "Input Registers: " << std::endl;

        for (std::pair<uint16_t, uint16_t> pair : it->second->input_registers) {
            std::cout << pair.first << ":" << pair.second << std::endl;
        }

        std::cout << "Generic Supported Functions:" << std::endl;

        for (const uint8_t& function : it->second->generic_supported_functions)
            std::cout << unsigned(function) << ", ";

        std::cout << std::endl;

        std::cout << "Specific Supported Functions:" << std::endl;

        for (const uint8_t& function : it->second->specific_supported_functions)
            std::cout << unsigned(function) << ", ";

        std::cout << std::endl;

        for (addresses_it = it->second->addresses_map.begin();
             addresses_it != it->second->addresses_map.end(); addresses_it++) {
            std::cout << "Address: " << addresses_it->second->address
                << std::endl;
            std::cout << "Writable: " << addresses_it->second->write
                << std::endl;
            std::cout << "Description: " << addresses_it->second->description
                << std::endl;
            std::cout << "Size: " << unsigned(addresses_it->second->size)
                << std::endl;
            std::cout << "Type: " << unsigned(addresses_it->second->type)
                << std::endl;

            std::cout << "Possible values: " << std::endl;

            for (union value_type value
                 : addresses_it->second->possible_values) {

                if (addresses_it->second->type == XLS_FLOAT_TYPE)
                    std::cout << value.f << ", ";
                else
                    std::cout << value.i << ", ";
            }

            std::cout << std::endl;

            std::cout << "Possible ranges: " << std::endl;

            for (std::pair<union value_type, union value_type> pair
                 : addresses_it->second->possible_ranges) {

                if (addresses_it->second->type == XLS_FLOAT_TYPE)
                    std::cout << pair.first.f << ":" << pair.second.f
                        << std::endl;
                else
                    std::cout << pair.first.i << ":" << pair.second.i
                        << std::endl;
            }

            std::cout << std::endl;
        }

        std::cout << std::endl;
    }
}

int main(int argc, char **argv)
{
    pcap_t *pcap_handler;
    struct bpf_program filter;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char const *device = "lo";
    int snapshot_len = 1028;
    int promiscuous = 1;
    int timeout = 1000;
    int res;

    // list_devs();

    //display_xls_config_file(XLS_CONFIG_FILE_NAME);
    extract_data_from_xls_config_file(XLS_CONFIG_FILE_NAME);
    display_devices();

    pcap_handler = pcap_open_live(device, snapshot_len, promiscuous, timeout,
                                  error_buffer);

    if (!pcap_handler) {
        std::cout << "Error while opening device" << std::endl;

        return 1;
    }

    // adding filter to capture only tcp packets
    //res = pcap_compile(pcap_handler, &filter, "tcp", 0,
    //                   PCAP_NETMASK_UNKNOWN);

    //if(res) {
    //    printf("pcap_compile failed\n");
    //    pcap_close(pcap_handler);

    //    return 1;
    //}

    //res = pcap_setfilter(pcap_handler, &filter);

    //if(res) {
    //    printf("pcap_setfilter failed\n");
    //    pcap_close(pcap_handler);

    //    return 1;
    //}

    pcap_loop(pcap_handler, -1, my_packet_handler, NULL);
    pcap_close(pcap_handler);

    return 0;
}
