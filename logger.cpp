/* Compile with: g++ logger.c -lpcap */
#include <iostream>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <unordered_set>

#include "logger.h"

std::unordered_set<uint16_t> modbus_queries;

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

void my_packet_handler(uint8_t *args, const struct pcap_pkthdr *header,
                       const uint8_t *packet)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *ethernet_header;
    struct modbus_tcp_generic *modbus;
    struct modbus_read_query read_query;
    struct modbus_read_response read_response;
    struct modbus_single_write single_write_packet;
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

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    // std::cout << "Total packet available: " << header->caplen << " bytes" <<
    // std::endl;

    // std::cout << "Expected packet size: " << header->len << " bytes" <<
    // std::endl;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    // std::cout << "IP header length (IHL) in bytes: " << ip_header_length <<
    // std::endl;

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        std::cout << "Not a TCP packet" << std::endl << std::endl;

        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    // std::cout << "TCP header length in bytes: " << tcp_header_length <<
    // std::endl;

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    // std::cout << "Size of all headers combined: " << total_headers_size <<
    // " bytes" << std::endl;
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
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

    switch (modbus->function_code) {
    case READ_COIL_STATUS:
        std::cout << "READ COIL STATUS" << std::endl;

        if (query_packet) {
            get_modbus_read_query(&read_query, payload);

            std::cout << "starting address: " << read_query.starting_address
                << std::endl;
            std::cout << "num of points: " << read_query.num_of_points
                << std::endl;
        } else {
            get_modbus_read_response(&read_response, payload);

            std::cout << "byte count: " << unsigned(read_response.byte_count)
                << std::endl;

            std::cout << "first byte of data: "
                << unsigned(read_response.data[0]) << std::endl;
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
        } else {
            get_modbus_read_response(&read_response, payload);

            std::cout << "byte count: " << unsigned(read_response.byte_count)
                << std::endl;

            std::cout << "first byte of data: "
                << unsigned(read_response.data[0]) << std::endl;
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

        break;
    case PRESET_SINGLE_REGISTER:
        std::cout << "PRESET SINGLE REGISTER" << std::endl;

        get_modbus_single_write(&single_write_packet, payload);

        std::cout << "address: " << single_write_packet.address << std::endl;
        std::cout << "value: " << single_write_packet.value << std::endl;

        break;
    case READ_EXCEPTION_STATUS:
        break;
    case FORCE_MULTIPLE_COILS:
        break;
    case PRESET_MULTIPLE_REGISTERS:
        break;
    case REPORT_SLAVE_ID:
        break;
    default:
        std::cout << "Function code decoding not yet implemented" << std::endl;
    }

    std::cout << std::endl;
}

int main(int argc, char **argv) {
    pcap_t *pcap_handler;
    struct bpf_program filter;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char const *device = "lo";
    int snapshot_len = 1028;
    int promiscuous = 1;
    int timeout = 1000;
    int res;

    //list_devs();

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
