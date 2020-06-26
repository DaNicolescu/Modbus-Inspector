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
#include "utils.h"
#include "db.h"

std::unordered_map<uint16_t, struct modbus_aggregate*> modbus_aggregated_frames;
std::unordered_map<uint8_t, struct device_struct*> devices_map;
struct db_manager *db;

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
        std::cout << current_dev->name << " " << (current_dev->description
            ? current_dev->description : "(no description)") << std::endl;

        current_dev = current_dev->next;
    }

    if (all_devs)
        pcap_freealldevs(all_devs);
}

bool modbus_frame_is_query(uint16_t transaction_id)
{
    if (modbus_aggregated_frames.find(transaction_id)
        == modbus_aggregated_frames.end())
        return true;

    return false;
}

struct device_struct *get_device(uint8_t slave_id)
{
    std::unordered_map<uint8_t, struct device_struct*>::iterator it;

    it = devices_map.find(slave_id);

    if (it != devices_map.end())
        return it->second;

    return NULL;
}

void modbus_packet_handler(uint8_t *args, const struct pcap_pkthdr *header,
                           const uint8_t *packet)
{
    struct ether_header *ethernet_header;
    struct modbus_tcp_generic *modbus_generic;
    struct modbus_read_query *read_query;
    struct modbus_read_response *read_response;
    struct modbus_single_write *single_write_packet;
    struct modbus_tcp_generic *exception_status_request;
    struct modbus_exception_status_response *exception_status_response;
    struct modbus_diagnostics *diagnostics_request;
    struct modbus_diagnostics *diagnostics_response;
    struct modbus_tcp_generic *event_counter_request;
    struct modbus_event_counter_response *event_counter_response;
    struct modbus_tcp_generic *event_log_request;
    struct modbus_event_log_response *event_log_response;
    struct modbus_multiple_write_query *multiple_write_query;
    struct modbus_multiple_write_response *multiple_write_response;
    struct modbus_aggregate *modbus_aggregated_frame;
    struct modbus_tcp_generic *report_slave_id_request;
    struct modbus_report_slave_id_response *report_slave_id_response;
    struct modbus_exception *exception;
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
    std::string errors;

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

    modbus_generic = get_modbus_tcp_generic(payload);

    query_packet = modbus_frame_is_query(modbus_generic->transaction_id);

    if (query_packet) {
        modbus_aggregated_frame = new modbus_aggregate;
        modbus_aggregated_frame->query = NULL;
        modbus_aggregated_frame->response = NULL;
        uint16_t transaction_id = modbus_generic->transaction_id;
        modbus_aggregated_frames.insert(std::pair<uint16_t,
            struct modbus_aggregate*>(transaction_id, modbus_aggregated_frame));
    } else {
        modbus_aggregated_frame = modbus_aggregated_frames.find(
            modbus_generic->transaction_id)->second;
        modbus_aggregated_frames.erase(modbus_generic->transaction_id);
    }

    dev = get_device(modbus_generic->unit_id);

    if (!dev) {
        errors = "The device with slave id "
            + std::to_string(modbus_generic->unit_id)
            + " does not exist";

        db->add_modbus_generic(modbus_generic, 0, errors);

        std::cout << errors << std::endl;
        std::cout << std::endl;

        return;
    }

    if (modbus_generic->function_code > 0x80) {
        exception = get_modbus_exception(payload);

        db->add_exception(exception);
        display_modbus_exception(exception);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->function_code += 0x80;
            modbus_aggregated_frame->response = exception;
            db->add_aggregated_exception_frame(modbus_aggregated_frame);
        }

        return;
    }

    if (!dev->supported_function(modbus_generic->function_code)) {
        errors = "Function code "
            + std::to_string(modbus_generic->function_code)
            + " not supported";

        db->add_modbus_generic(modbus_generic, 0, errors);

        std::cout << errors << std::endl;
        std::cout << std::endl;

        return;
    }

    switch (modbus_generic->function_code) {
    case READ_COIL_STATUS:
        std::cout << "READ COIL STATUS" << std::endl;

        if (query_packet) {
            read_query = get_modbus_read_query(payload);

            if (!dev->valid_read_coils_addresses(read_query->starting_address,
                                                 read_query->num_of_points)) {
                errors = "Invalid addresses";

                db->add_read_query(read_query, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_read_query(read_query);
            } else {
                db->add_read_query(read_query);

                display_modbus_read_query(read_query);
                dev->display_addresses(read_query->starting_address
                                       + COILS_OFFSET,
                                       read_query->num_of_points);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = read_query;
            }
        } else {
            read_response = get_modbus_read_response(payload);

            db->add_read_response(read_response);
            display_modbus_read_response(read_response);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = read_response;
                dev->display_addresses(modbus_aggregated_frame);
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case READ_INPUT_STATUS:
        std::cout << "READ INPUT STATUS" << std::endl;

        if (query_packet) {
            read_query = get_modbus_read_query(payload);

            if (!dev->valid_inputs_addresses(read_query->starting_address,
                                             read_query->num_of_points)) {
                errors = "Invalid addresses";

                db->add_read_query(read_query, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_read_query(read_query);
            } else {
                db->add_read_query(read_query);

                display_modbus_read_query(read_query);
                dev->display_addresses(read_query->starting_address
                                       + INPUTS_OFFSET,
                                       read_query->num_of_points);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = read_query;
            }
        } else {
            read_response = get_modbus_read_response(payload);

            db->add_read_response(read_response);
            display_modbus_read_response(read_response);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = read_response;
                dev->display_addresses(modbus_aggregated_frame);
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case READ_HOLDING_REGISTERS:
        std::cout << "READ HOLDING REGISTERS" << std::endl;

        if (query_packet) {
            read_query = get_modbus_read_query(payload);

            if (!dev->valid_read_hld_regs_addresses(
                    read_query->starting_address,
                    read_query->num_of_points)) {
                errors = "Invalid addresses";

                db->add_read_query(read_query, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_read_query(read_query);
            } else {
                db->add_read_query(read_query);

                display_modbus_read_query(read_query);
                dev->display_addresses(read_query->starting_address
                                       + HLD_REGS_OFFSET,
                                       read_query->num_of_points);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = read_query;
            }
        } else {
            read_response = get_modbus_read_response(payload);

            db->add_read_response(read_response);
            display_modbus_read_response(read_response);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = read_response;
                dev->display_addresses(modbus_aggregated_frame);
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case READ_INPUT_REGISTERS:
        std::cout << "READ INPUT REGISTERS" << std::endl;

        if (query_packet) {
            read_query = get_modbus_read_query(payload);

            if (!dev->valid_input_regs_addresses(read_query->starting_address,
                                                 read_query->num_of_points)) {
                errors = "Invalid addresses";

                db->add_read_query(read_query, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_read_query(read_query);
            } else {
                db->add_read_query(read_query);

                display_modbus_read_query(read_query);
                dev->display_addresses(read_query->starting_address
                                       + INPUT_REGS_OFFSET,
                                       read_query->num_of_points);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = read_query;
            }
        } else {
            read_response = get_modbus_read_response(payload);

            db->add_read_response(read_response);
            display_modbus_read_response(read_response);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = read_response;
                dev->display_addresses(modbus_aggregated_frame);
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case FORCE_SINGLE_COIL:
        std::cout << "FORCE SINGLE COIL" << std::endl;

        single_write_packet = get_modbus_single_write(payload);

        if (query_packet) {
            if (!dev->valid_write_coils_addresses(single_write_packet->address,
                                                  1)) {
                errors = "Invalid address";

                db->add_single_write(single_write_packet, 0, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_single_write(single_write_packet, true);
            } else {
                db->add_single_write(single_write_packet, 0);

                display_modbus_single_write(single_write_packet, true);
                dev->display_addresses(single_write_packet->address
                                       + COILS_OFFSET,
                                       1);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = single_write_packet;
            }
        } else {
            db->add_single_write(single_write_packet, 1);
            display_modbus_single_write(single_write_packet, false);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = single_write_packet;
                dev->display_addresses(modbus_aggregated_frame);
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case PRESET_SINGLE_REGISTER:
        std::cout << "PRESET SINGLE REGISTER" << std::endl;

        single_write_packet = get_modbus_single_write(payload);

        if (query_packet) {
            if (!dev->valid_write_hld_regs_addresses(
                    single_write_packet->address, 1)) {
                errors = "Invalid address";

                db->add_single_write(single_write_packet, 0, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_single_write(single_write_packet, true);
            } else {
                db->add_single_write(single_write_packet, 0);

                display_modbus_single_write(single_write_packet, true);
                dev->display_addresses(single_write_packet->address
                                       + HLD_REGS_OFFSET, 1);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = single_write_packet;
            }
        } else {
            db->add_single_write(single_write_packet, 1);
            display_modbus_single_write(single_write_packet, false);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = single_write_packet;
                dev->display_addresses(modbus_aggregated_frame);
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case READ_EXCEPTION_STATUS:
        std::cout << "READ EXCEPTION STATUS" << std::endl;

        if (query_packet) {
            exception_status_request = get_modbus_tcp_generic(payload);
            db->add_modbus_generic(exception_status_request, 0);

            display_modbus_tcp_generic(exception_status_request, true);

            modbus_aggregated_frame->function_code =
                exception_status_request->function_code;
            modbus_aggregated_frame->query = exception_status_request;
        } else {
            exception_status_response =
                get_modbus_exception_status_response(payload);

            db->add_exception_status_response(exception_status_response);
            display_modbus_exception_status_response(exception_status_response);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = exception_status_response;
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case DIAGNOSTICS:
        std::cout << "DIAGNOSTICS" << std::endl;

        if (query_packet) {
            diagnostics_request = get_modbus_diagnostics(payload);
            db->add_diagnostics(diagnostics_request, 0);

            display_modbus_diagnostics(diagnostics_request, true);

            modbus_aggregated_frame->function_code =
                diagnostics_request->generic_header.function_code;
            modbus_aggregated_frame->query = diagnostics_request;
        } else {
            diagnostics_response = get_modbus_diagnostics(payload);
            db->add_diagnostics(diagnostics_response, 1);

            display_modbus_diagnostics(diagnostics_response, false);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = diagnostics_response;
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case FETCH_COMM_EVENT_COUNTER:
        std::cout << "FETCH COMM EVENT COUNTER" << std::endl;

        if (query_packet) {
            event_counter_request = get_modbus_tcp_generic(payload);
            db->add_modbus_generic(event_counter_request, 0);

            display_modbus_tcp_generic(event_counter_request, true);

            modbus_aggregated_frame->function_code =
                event_counter_request->function_code;
            modbus_aggregated_frame->query = event_counter_request;
        } else {
            event_counter_response = get_modbus_event_counter_response(payload);

            db->add_event_counter_response(event_counter_response);
            display_modbus_event_counter_response(event_counter_response);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = event_counter_response;
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case FETCH_COMM_EVENT_LOG:
        std::cout << "FETCH COMM EVENT LOG" << std::endl;

        if (query_packet) {
            event_log_request = get_modbus_tcp_generic(payload);
            db->add_modbus_generic(event_log_request, 0);

            display_modbus_tcp_generic(event_log_request, true);

            modbus_aggregated_frame->function_code =
                event_log_request->function_code;
            modbus_aggregated_frame->query = event_log_request;
        } else {
            event_log_response = get_modbus_event_log_response(payload);

            db->add_event_log_response(event_log_response);
            display_modbus_event_log_response(event_log_response);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = event_log_response;
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    case FORCE_MULTIPLE_COILS:
        std::cout << "FORCE MULTIPLE COILS" << std::endl;

        if (query_packet) {
            multiple_write_query = get_modbus_multiple_write_query(payload);

            if (!dev->valid_write_coils_addresses(
                    multiple_write_query->starting_address,
                    multiple_write_query->num_of_points)) {
                errors = "Invalid addresses";

                db->add_multiple_write_query(multiple_write_query, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_multiple_write_query(multiple_write_query);
            } else {
                db->add_multiple_write_query(multiple_write_query);

                display_modbus_multiple_write_query(multiple_write_query);
                dev->display_addresses(multiple_write_query->starting_address
                                       + COILS_OFFSET,
                                       multiple_write_query->num_of_points);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = multiple_write_query;
            }
        } else {
            multiple_write_response = get_modbus_multiple_write_response(
                payload);

            if (!dev->valid_write_coils_addresses(
                    multiple_write_response->starting_address,
                    multiple_write_response->num_of_points)) {
                errors = "Invalid addresses";

                db->add_multiple_write_response(multiple_write_response,
                                                errors);
            } else {
                db->add_multiple_write_response(multiple_write_response);

                display_modbus_multiple_write_response(multiple_write_response);
                dev->display_addresses(multiple_write_response->starting_address
                                       + COILS_OFFSET,
                                       multiple_write_response->num_of_points);

                if (modbus_aggregated_frame->query != NULL) {
                    modbus_aggregated_frame->response = multiple_write_response;
                    dev->display_addresses(modbus_aggregated_frame);
                    db->add_aggregated_frame(dev, modbus_aggregated_frame);
                }
            }
        }

        break;
    case PRESET_MULTIPLE_REGISTERS:
        std::cout << "PRESET MULTIPLE REGISTERS" << std::endl;

        if (query_packet) {
            multiple_write_query = get_modbus_multiple_write_query(payload);

            if (!dev->valid_write_hld_regs_addresses(
                    multiple_write_query->starting_address,
                    multiple_write_query->num_of_points)) {
                errors = "Invalid addresses";

                db->add_multiple_write_query(multiple_write_query, errors);

                std::cout << errors << std::endl;
                std::cout << std::endl;

                display_modbus_multiple_write_query(multiple_write_query);
            } else {
                db->add_multiple_write_query(multiple_write_query);

                display_modbus_multiple_write_query(multiple_write_query);
                dev->display_addresses(multiple_write_query->starting_address
                                       + HLD_REGS_OFFSET,
                                       multiple_write_query->num_of_points);

                modbus_aggregated_frame->function_code =
                    modbus_generic->function_code;
                modbus_aggregated_frame->query = multiple_write_query;
            }
        } else {
            multiple_write_response = get_modbus_multiple_write_response(
                payload);

            if (!dev->valid_write_hld_regs_addresses(
                    multiple_write_response->starting_address,
                    multiple_write_response->num_of_points)) {
                errors = "Invalid addresses";

                db->add_multiple_write_response(multiple_write_response,
                                                errors);
            } else {
                db->add_multiple_write_response(multiple_write_response);

                display_modbus_multiple_write_response(multiple_write_response);
                dev->display_addresses(multiple_write_response->starting_address
                                       + HLD_REGS_OFFSET,
                                       multiple_write_response->num_of_points);

                if (modbus_aggregated_frame->query != NULL) {
                    modbus_aggregated_frame->response = multiple_write_response;
                    dev->display_addresses(modbus_aggregated_frame);
                    db->add_aggregated_frame(dev, modbus_aggregated_frame);
                }
            }
        }

        break;
    case REPORT_SLAVE_ID:
        std::cout << "REPORT SLAVE ID" << std::endl;

        if (query_packet) {
            report_slave_id_request = get_modbus_tcp_generic(payload);
            db->add_modbus_generic(report_slave_id_request, 0);

            display_modbus_tcp_generic(report_slave_id_request, true);

            modbus_aggregated_frame->function_code =
                report_slave_id_request->function_code;
            modbus_aggregated_frame->query = report_slave_id_request;
        } else {
            report_slave_id_response = get_modbus_report_slave_id_response(
                payload);

            db->add_report_slave_id_response(report_slave_id_response);
            display_modbus_report_slave_id_response(report_slave_id_response);

            modbus_aggregated_frame->response = report_slave_id_response;

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->response = report_slave_id_response;
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
            }
        }

        break;
    default:
        std::cout << "Function code decoding not yet implemented" << std::endl;
    }

    std::cout << std::endl;
}

void display_devices()
{
    std::unordered_map<uint8_t, struct device_struct*>::iterator it;

    for (it = devices_map.begin(); it != devices_map.end(); it++) {
        it->second->display();
    }
}

void add_addresses_to_db(struct db_manager *db)
{
    uint8_t slave_id;
    struct device_struct *dev;
    std::unordered_map<uint8_t, struct device_struct*>::iterator it;
    std::unordered_map<uint16_t, struct address_struct*>::iterator addresses_it;

    for (it = devices_map.begin(); it != devices_map.end(); it++) {
        slave_id = it->first;
        dev = it->second;

        for (addresses_it = dev->addresses_map.begin();
            addresses_it != dev->addresses_map.end(); addresses_it++) {
            db->add_address(addresses_it->second, slave_id);
        }
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

    db = new db_manager;

    db->open();
    db->create_database("modbus");
    db->create_tables();

    // list_interfaces();

    //display_xls_config_file(XLS_CONFIG_FILE_NAME);
    extract_data_from_xls_config_file(XLS_CONFIG_FILE_NAME, devices_map);
    display_devices();

    add_addresses_to_db(db);

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

    pcap_loop(pcap_handler, -1, modbus_packet_handler, NULL);
    pcap_close(pcap_handler);
    db->close();

    return 0;
}
