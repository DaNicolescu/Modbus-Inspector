/* Compile with: g++ logger.c -lpcap */
#include <iostream>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <unordered_map>

#include "logger.h"

std::unordered_map<uint16_t, uint8_t> modbus_queries;

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

void my_packet_handler(uint8_t *args, const struct pcap_pkthdr *header,
		       const uint8_t *packet)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *ethernet_header;
    struct modbus_tcp *modbus;
    const uint8_t *ip_header;
    const uint8_t *tcp_header;
    const uint8_t *payload;
    int ethernet_header_length = ETH_HDR_LEN;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

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

    modbus = (struct modbus_tcp*) payload;

    printf("transaction id: %d\n", htons(modbus->transaction_id));
    printf("protocol id: %d\n", htons(modbus->protocol_id));
    printf("length: %d\n", htons(modbus->length));
    printf("slave id: %d\n", modbus->unit_id);
    printf("function code: %d\n", modbus->function_code);

    // Trebuie facut un map pentru a determina folosind transaction_id carei
    // cereri raspunde un slave

    printf("\n");
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
	printf("error while opening device\n");

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
