/* Compile with: g++ logger.c -lpcap */
#include <iostream>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <unordered_set>

#include "logger.h"
#include "XlsReader.h"
#include "device_struct.h"
#include "modbus.h"
#include "config.h"

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
    extract_data_from_xls_config_file(XLS_CONFIG_FILE_NAME, devices_map);
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
