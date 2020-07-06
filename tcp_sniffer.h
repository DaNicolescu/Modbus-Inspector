#ifndef TCP_SNIFFER_H
#define TCP_SNIFFER_H

#include <string>
#include <pcap.h>

#define ETH_HDR_LEN                 0x0E

namespace tcp_sniffer {
    void list_interfaces();
    void packet_handler(uint8_t *args, const struct pcap_pkthdr *header,
        const uint8_t *packet);

    int init(std::string interface);
    int run();
    void close_sniffer();
};

#endif
