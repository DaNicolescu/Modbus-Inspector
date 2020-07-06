#include <iostream>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "tcp_sniffer.h"
#include "logger.h"

namespace tcp_sniffer {
    pcap_t *pcap_handler;

    void list_interfaces()
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
            printf("%-17s %s\n", current_dev->name, (current_dev->description
                ? current_dev->description : "(no description)"));

            current_dev = current_dev->next;
        }

        if (all_devs)
            pcap_freealldevs(all_devs);
    }

    void packet_handler(uint8_t *args, const struct pcap_pkthdr *header,
        const uint8_t *packet)
    {
        struct ether_header *ethernet_header;
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

        // std::cout << "Total packet available: " << header->caplen
        // << " bytes" << std::endl;

        // std::cout << "Expected packet size: " << header->len << " bytes" <<
        // std::endl;

        ip_header = packet + ethernet_header_length;
        ip_header_length = ((*ip_header) & 0x0F) * 4;

        // std::cout << "IP header length (IHL) in bytes: " << ip_header_length
        // << std::endl;

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

        // std::cout << "Size of all headers combined: " << total_headers_size
        // << " bytes" << std::endl;

        payload_length = header->caplen
            - (ethernet_header_length + ip_header_length + tcp_header_length);

        // std::cout << "Payload size: " << payload_length << " bytes"
        // << std::endl;

        payload = packet + total_headers_size;

        if (payload_length <= 0 || payload_length > 260)
            return;

        logger::modbus_packet_handler(payload);
    }

    int init(std::string interface)
    {
        struct bpf_program filter;
        char error_buffer[PCAP_ERRBUF_SIZE];
        int snapshot_len = 1028;
        int promiscuous = 1;
        int timeout = 1000;
        int res;

        pcap_handler = pcap_open_live(interface.c_str(), snapshot_len,
                                      promiscuous, timeout, error_buffer);

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

        return 0;
    }

    int run()
    {
        pcap_loop(pcap_handler, -1, packet_handler, NULL);
    }

    void close_sniffer()
    {
        if (pcap_handler) {
            pcap_breakloop(pcap_handler);
            pcap_close(pcap_handler);
        }
    }
}
