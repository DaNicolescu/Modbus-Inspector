/* Compile with: g++ logger.c -lpcap */
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include "logger.h"
#include "XlsReader.h"
#include "device_struct.h"
#include "modbus.h"
#include "config.h"
#include "utils.h"
#include "db.h"

namespace logger {
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

    void handle_read_query(const struct device_struct *dev,
        struct modbus_read_query *read_query, struct modbus_aggregate
        *modbus_aggregated_frame, uint16_t address_offset)
    {
        db->add_read_query(read_query);

        if (display) {
            display_modbus_read_query(read_query);
            dev->display_addresses(read_query->starting_address
                + address_offset, read_query->num_of_points);
        }

        modbus_aggregated_frame->function_code =
            read_query->generic_header.function_code;
        modbus_aggregated_frame->query = read_query;
    }

    void handle_read_query(const struct modbus_read_query *read_query,
        const std::string &errors)
    {
        db->add_read_query(read_query, errors);

        if (display) {
            display_modbus_read_query(read_query);

            std::cout << errors << std::endl;
            std::cout << std::endl;
        }
    }

    void handle_read_response(const struct device_struct *dev,
        struct modbus_read_response *read_response,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_read_response(read_response);

        if (display)
            display_modbus_read_response(read_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = read_response;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);

            if (display)
                dev->display_addresses(modbus_aggregated_frame);
        }
    }

    void handle_single_write_query(const struct device_struct *dev,
        struct modbus_single_write *single_write_frame,
        struct modbus_aggregate *modbus_aggregated_frame,
        uint16_t address_offset)
    {
        db->add_single_write(single_write_frame, QUERY_FRAME);

        if (display) {
            display_modbus_single_write(single_write_frame, true);
            dev->display_addresses(single_write_frame->address + address_offset,
                1);
        }

        modbus_aggregated_frame->function_code =
            single_write_frame->generic_header.function_code;
        modbus_aggregated_frame->query = single_write_frame;
    }

    void handle_single_write_query(const struct modbus_single_write
        *single_write_frame, const std::string &errors)
    {
        db->add_single_write(single_write_frame, QUERY_FRAME, errors);

        if (display) {
            display_modbus_single_write(single_write_frame, true);

            std::cout << errors << std::endl;
            std::cout << std::endl;
        }
    }

    void handle_single_write_response(const struct device_struct *dev,
        struct modbus_single_write *single_write_frame,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_single_write(single_write_frame, RESPONSE_FRAME);

        if (display)
            display_modbus_single_write(single_write_frame, false);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = single_write_frame;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);

            if (display)
                dev->display_addresses(modbus_aggregated_frame);
        }
    }

    void handle_read_exception_status_query(struct modbus_tcp_generic
        *exception_status_query, struct modbus_aggregate
        *modbus_aggregated_frame)
    {
        db->add_modbus_generic(exception_status_query, QUERY_FRAME);

        if (display)
            display_modbus_tcp_generic(exception_status_query, true);

        modbus_aggregated_frame->function_code =
            exception_status_query->function_code;
        modbus_aggregated_frame->query = exception_status_query;
    }

    void handle_read_exception_status_response(const struct device_struct
        *dev, struct modbus_exception_status_response
        *exception_status_response, struct modbus_aggregate
        *modbus_aggregated_frame)
    {
        db->add_exception_status_response(exception_status_response);

        if (display)
            display_modbus_exception_status_response(exception_status_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = exception_status_response;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_diagnostics_query(struct modbus_diagnostics
        *diagnostics_query, struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_diagnostics(diagnostics_query, QUERY_FRAME);

        if (display)
            display_modbus_diagnostics(diagnostics_query, true);

        modbus_aggregated_frame->function_code =
            diagnostics_query->generic_header.function_code;
        modbus_aggregated_frame->query = diagnostics_query;
    }

    void handle_diagnostics_response(const struct device_struct *dev,
        struct modbus_diagnostics *diagnostics_response,
        struct modbus_aggregate* modbus_aggregated_frame)
    {
        db->add_diagnostics(diagnostics_response, RESPONSE_FRAME);

        if (display)
            display_modbus_diagnostics(diagnostics_response, false);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = diagnostics_response;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_fetch_comm_event_counter_query(struct modbus_tcp_generic
        *event_counter_query, struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_modbus_generic(event_counter_query, QUERY_FRAME);

        if (display)
            display_modbus_tcp_generic(event_counter_query, true);

        modbus_aggregated_frame->function_code =
            event_counter_query->function_code;
        modbus_aggregated_frame->query = event_counter_query;
    }

    void handle_fetch_comm_event_counter_response(const struct device_struct
        *dev, struct modbus_event_counter_response *event_counter_response,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_event_counter_response(event_counter_response);

        if (display)
            display_modbus_event_counter_response(event_counter_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = event_counter_response;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_fetch_comm_event_log_query(struct modbus_tcp_generic
        *event_log_query, struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_modbus_generic(event_log_query, QUERY_FRAME);

        if (display)
            display_modbus_tcp_generic(event_log_query, true);

        modbus_aggregated_frame->function_code = event_log_query->function_code;
        modbus_aggregated_frame->query = event_log_query;
    }

    void handle_fetch_comm_event_log_response(const struct device_struct
        *dev, struct modbus_event_log_response *event_log_response,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_event_log_response(event_log_response);

        if (display)
            display_modbus_event_log_response(event_log_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = event_log_response;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_force_multiple_write_query(const struct device_struct *dev,
        struct modbus_multiple_write_query *multiple_write_query,
        struct modbus_aggregate *modbus_aggregated_frame,
        uint16_t address_offset)
    {
        db->add_multiple_write_query(multiple_write_query);

        if (display) {
            display_modbus_multiple_write_query(multiple_write_query);
            dev->display_addresses(multiple_write_query->starting_address
                + address_offset, multiple_write_query->num_of_points);
        }

        modbus_aggregated_frame->function_code =
            multiple_write_query->generic_header.function_code;
        modbus_aggregated_frame->query = multiple_write_query;
    }

    void handle_force_multiple_write_query(
        struct modbus_multiple_write_query *multiple_write_query,
        const std::string &errors)
    {
        db->add_multiple_write_query(multiple_write_query, errors);

        if (display) {
            display_modbus_multiple_write_query(multiple_write_query);

            std::cout << errors << std::endl;
            std::cout << std::endl;
        }
    }

    void handle_force_multiple_write_response(const struct device_struct
        *dev, struct modbus_multiple_write_response *multiple_write_response,
        struct modbus_aggregate *modbus_aggregated_frame,
        uint16_t address_offset)
    {
        db->add_multiple_write_response(multiple_write_response);

        if (display) {
            display_modbus_multiple_write_response(multiple_write_response);
            dev->display_addresses(multiple_write_response->starting_address
                + address_offset, multiple_write_response->num_of_points);
        }

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = multiple_write_response;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);

            if (display)
                dev->display_addresses(modbus_aggregated_frame);
        }
    }

    void handle_force_multiple_write_response(
        struct modbus_multiple_write_response *multiple_write_response,
        const std::string &errors)
    {
        db->add_multiple_write_response(multiple_write_response, errors);
    }

    void handle_report_slave_id_request(struct modbus_tcp_generic
        *report_slave_id_request, struct modbus_aggregate
        *modbus_aggregated_frame)
    {
        db->add_modbus_generic(report_slave_id_request, QUERY_FRAME);

        if (display)
            display_modbus_tcp_generic(report_slave_id_request, true);

        modbus_aggregated_frame->function_code =
            report_slave_id_request->function_code;
        modbus_aggregated_frame->query = report_slave_id_request;
    }

    void handle_report_slave_id_response(struct device_struct *dev,
        struct modbus_report_slave_id_response *report_slave_id_response,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_report_slave_id_response(report_slave_id_response);

        if (display)
            display_modbus_report_slave_id_response(report_slave_id_response);

        modbus_aggregated_frame->response = report_slave_id_response;

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = report_slave_id_response;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_mask_write_query(const struct device_struct *dev,
        struct modbus_mask_write *mask_write,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_mask_write(mask_write, QUERY_FRAME);

        if (display) {
            display_modbus_mask_write(mask_write, true);
            dev->display_addresses(mask_write->address + HLD_REGS_OFFSET, 1);
        }

        modbus_aggregated_frame->function_code =
            mask_write->generic_header.function_code;
        modbus_aggregated_frame->query = mask_write;
    }

    void handle_mask_write_query(const struct modbus_mask_write *mask_write,
        const std::string &errors)
    {
        db->add_mask_write(mask_write, QUERY_FRAME, errors);

        if (display) {
            display_modbus_mask_write(mask_write, true);

            std::cout << errors << std::endl;
            std::cout << std::endl;
        }
    }

    void handle_mask_write_response(const struct device_struct *dev,
        struct modbus_mask_write *mask_write,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        db->add_mask_write(mask_write, RESPONSE_FRAME);

        if (display) {
            display_modbus_mask_write(mask_write, false);
            dev->display_addresses(mask_write->address + HLD_REGS_OFFSET, 1);
        }

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = mask_write;
            db->add_aggregated_frame(dev, modbus_aggregated_frame);

            if (display)
                dev->display_addresses(modbus_aggregated_frame);
        }
    }

    void handle_mask_write_response(struct modbus_mask_write *mask_write,
        const std::string &errors)
    {
        db->add_mask_write(mask_write, RESPONSE_FRAME, errors);
    }

    void modbus_packet_handler(uint8_t *args, const struct pcap_pkthdr
        *header, const uint8_t *packet)
    {
        struct ether_header *ethernet_header;
        struct modbus_tcp_generic *modbus_generic;
        struct modbus_read_query *read_query;
        struct modbus_read_response *read_response;
        struct modbus_single_write *single_write_packet;
        struct modbus_tcp_generic *exception_status_query;
        struct modbus_exception_status_response *exception_status_response;
        struct modbus_diagnostics *diagnostics_query;
        struct modbus_diagnostics *diagnostics_response;
        struct modbus_tcp_generic *event_counter_query;
        struct modbus_event_counter_response *event_counter_response;
        struct modbus_tcp_generic *event_log_query;
        struct modbus_event_log_response *event_log_response;
        struct modbus_multiple_write_query *multiple_write_query;
        struct modbus_multiple_write_response *multiple_write_response;
        struct modbus_aggregate *modbus_aggregated_frame;
        struct modbus_tcp_generic *report_slave_id_query;
        struct modbus_report_slave_id_response *report_slave_id_response;
        struct modbus_mask_write *mask_write;
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
        bool query_frame;
        std::string errors;
        bool valid_frame;

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

        query_frame = modbus_frame_is_query(modbus_generic->transaction_id);

        if (query_frame) {
            modbus_aggregated_frame = new modbus_aggregate;
            modbus_aggregated_frame->query = NULL;
            modbus_aggregated_frame->response = NULL;
            uint16_t transaction_id = modbus_generic->transaction_id;
            modbus_aggregated_frames.insert(std::pair<uint16_t,
                struct modbus_aggregate*>(transaction_id,
                                          modbus_aggregated_frame));
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

            if (display)
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
            if (query_frame) {
                read_query = get_modbus_read_query(payload);

                valid_frame = dev->valid_read_coils_addresses(
                    read_query->starting_address, read_query->num_of_points);

                if (valid_frame) {
                    handle_read_query(dev, read_query, modbus_aggregated_frame,
                                      COILS_OFFSET);
                } else {
                    handle_read_query(read_query, "Invalid addresses");
                }
            } else {
                read_response = get_modbus_read_response(payload);

                handle_read_response(dev, read_response,
                                     modbus_aggregated_frame);
            }

            break;
        case READ_INPUT_STATUS:
            if (query_frame) {
                read_query = get_modbus_read_query(payload);

                valid_frame =
                    dev->valid_inputs_addresses(read_query->starting_address,
                                                read_query->num_of_points);
                if (valid_frame) {
                    handle_read_query(dev, read_query, modbus_aggregated_frame,
                                      INPUTS_OFFSET);
                } else {
                    handle_read_query(read_query, "Invalid addresses");
                }
            } else {
                read_response = get_modbus_read_response(payload);

                handle_read_response(dev, read_response,
                                     modbus_aggregated_frame);
            }

            break;
        case READ_HOLDING_REGISTERS:
            if (query_frame) {
                read_query = get_modbus_read_query(payload);

                valid_frame = dev->valid_read_hld_regs_addresses(
                    read_query->starting_address,
                    read_query->num_of_points);

                if (valid_frame) {
                    handle_read_query(dev, read_query, modbus_aggregated_frame,
                                      HLD_REGS_OFFSET);
                } else {
                    handle_read_query(read_query, "Invalid addresses");
                }
            } else {
                read_response = get_modbus_read_response(payload);

                handle_read_response(dev, read_response,
                                     modbus_aggregated_frame);
            }

            break;
        case READ_INPUT_REGISTERS:
            if (query_frame) {
                read_query = get_modbus_read_query(payload);

                valid_frame = dev->valid_input_regs_addresses(
                    read_query->starting_address, read_query->num_of_points);

                if (valid_frame) {
                    handle_read_query(dev, read_query, modbus_aggregated_frame,
                                      INPUT_REGS_OFFSET);
                } else {
                    handle_read_query(read_query, "Invalid addresses");
                }
            } else {
                read_response = get_modbus_read_response(payload);

                handle_read_response(dev, read_response,
                                     modbus_aggregated_frame);
            }

            break;
        case FORCE_SINGLE_COIL:
            single_write_packet = get_modbus_single_write(payload);

            if (query_frame) {
                valid_frame = dev->valid_write_coils_addresses(
                    single_write_packet->address, 1);

                if (valid_frame) {
                    handle_single_write_query(dev, single_write_packet,
                                              modbus_aggregated_frame,
                                              COILS_OFFSET);
                } else {
                    handle_single_write_query(single_write_packet,
                                              "Invalid address");
                }
            } else {
                handle_single_write_response(dev, single_write_packet,
                                             modbus_aggregated_frame);
            }

            break;
        case PRESET_SINGLE_REGISTER:
            single_write_packet = get_modbus_single_write(payload);

            if (query_frame) {
                valid_frame = dev->valid_write_hld_regs_addresses(
                    single_write_packet->address, 1);

                if (valid_frame) {
                    handle_single_write_query(dev, single_write_packet,
                                              modbus_aggregated_frame,
                                              HLD_REGS_OFFSET);
                } else {
                    handle_single_write_query(single_write_packet,
                                              "Invalid address");
                }
            } else {
                handle_single_write_response(dev, single_write_packet,
                                             modbus_aggregated_frame);
            }

            break;
        case READ_EXCEPTION_STATUS:
            if (query_frame) {
                exception_status_query = get_modbus_tcp_generic(payload);

                handle_read_exception_status_query(exception_status_query,
                                                     modbus_aggregated_frame);
            } else {
                exception_status_response =
                    get_modbus_exception_status_response(payload);

                handle_read_exception_status_response(dev,
                                                      exception_status_response,
                                                      modbus_aggregated_frame);
            }

            break;
        case DIAGNOSTICS:
            if (query_frame) {
                diagnostics_query = get_modbus_diagnostics(payload);

                handle_diagnostics_query(diagnostics_query,
                                         modbus_aggregated_frame);
            } else {
                diagnostics_response = get_modbus_diagnostics(payload);

                handle_diagnostics_response(dev, diagnostics_response,
                                            modbus_aggregated_frame);
            }

            break;
        case FETCH_COMM_EVENT_COUNTER:
            if (query_frame) {
                event_counter_query = get_modbus_tcp_generic(payload);

                handle_fetch_comm_event_counter_query(event_counter_query,
                                                      modbus_aggregated_frame);
            } else {
                event_counter_response = get_modbus_event_counter_response(
                    payload);

                handle_fetch_comm_event_counter_response(dev,
                    event_counter_response, modbus_aggregated_frame);
            }

            break;
        case FETCH_COMM_EVENT_LOG:
            if (query_frame) {
                event_log_query = get_modbus_tcp_generic(payload);

                handle_fetch_comm_event_log_query(event_log_query,
                                                    modbus_aggregated_frame);
            } else {
                event_log_response = get_modbus_event_log_response(payload);

                handle_fetch_comm_event_log_response(dev, event_log_response,
                                                     modbus_aggregated_frame);
            }

            break;
        case FORCE_MULTIPLE_COILS:
            if (query_frame) {
                multiple_write_query = get_modbus_multiple_write_query(payload);

                valid_frame = dev->valid_write_coils_addresses(
                    multiple_write_query->starting_address,
                    multiple_write_query->num_of_points);

                if (valid_frame) {
                    handle_force_multiple_write_query(dev, multiple_write_query,
                                                      modbus_aggregated_frame,
                                                      COILS_OFFSET);
                } else {
                    handle_force_multiple_write_query(multiple_write_query,
                                                      "Invalid addresses");
                }
            } else {
                multiple_write_response = get_modbus_multiple_write_response(
                    payload);

                valid_frame = dev->valid_write_coils_addresses(
                    multiple_write_response->starting_address,
                    multiple_write_response->num_of_points);

                if (valid_frame) {
                    handle_force_multiple_write_response(dev,
                        multiple_write_response, modbus_aggregated_frame,
                        COILS_OFFSET);
                } else {
                    handle_force_multiple_write_response(
                        multiple_write_response, "Invalid addresses");
                }
            }

            break;
        case PRESET_MULTIPLE_REGISTERS:
            if (query_frame) {
                multiple_write_query = get_modbus_multiple_write_query(payload);

                valid_frame = dev->valid_write_hld_regs_addresses(
                    multiple_write_query->starting_address,
                    multiple_write_query->num_of_points);

                if (valid_frame) {
                    handle_force_multiple_write_query(dev, multiple_write_query,
                                                      modbus_aggregated_frame,
                                                      HLD_REGS_OFFSET);
                } else {
                    handle_force_multiple_write_query(multiple_write_query,
                                                      "Invalid addresses");
                }
            } else {
                multiple_write_response = get_modbus_multiple_write_response(
                    payload);

                valid_frame = !dev->valid_write_hld_regs_addresses(
                    multiple_write_response->starting_address,
                    multiple_write_response->num_of_points);

                if (valid_frame) {
                    handle_force_multiple_write_response(dev,
                        multiple_write_response, modbus_aggregated_frame,
                        HLD_REGS_OFFSET);
                } else {
                    handle_force_multiple_write_response(
                        multiple_write_response, "Invalid addresses");
                }
            }

            break;
        case REPORT_SLAVE_ID:
            if (query_frame) {
                report_slave_id_query = get_modbus_tcp_generic(payload);

                handle_report_slave_id_request(report_slave_id_query,
                                               modbus_aggregated_frame);
            } else {
                report_slave_id_response = get_modbus_report_slave_id_response(
                    payload);

                handle_report_slave_id_response(dev, report_slave_id_response,
                                                modbus_aggregated_frame);
            }

            break;
        case READ_FILE_RECORD:
            break;
        case WRITE_FILE_RECORD:
            break;
        case MASK_WRITE_REGISTER:
            mask_write = get_modbus_mask_write(payload);

            valid_frame = dev->valid_write_hld_regs_addresses(
                mask_write->address, 1);

            if (query_frame) {
                if (valid_frame) {
                    handle_mask_write_query(dev, mask_write,
                                            modbus_aggregated_frame);
                } else {
                    handle_mask_write_query(mask_write, "Invalid address");
                }
            } else {
                if (valid_frame) {
                    handle_mask_write_response(dev, mask_write,
                                               modbus_aggregated_frame);
                } else {
                    handle_mask_write_response(mask_write, "Invalid address");
                }
            }

            break;
        default:
            std::cout << "Function code decoding not yet implemented"
                << std::endl;
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
        std::unordered_map<uint16_t, struct address_struct*>::iterator
            addresses_it;

        for (it = devices_map.begin(); it != devices_map.end(); it++) {
            slave_id = it->first;
            dev = it->second;

            for (addresses_it = dev->addresses_map.begin();
                addresses_it != dev->addresses_map.end(); addresses_it++) {
                db->add_address(addresses_it->second, slave_id);
            }
        }
    }

    void display_help()
    {
        std::cout << "Modbus Logger" << std::endl;
        std::cout << "-h       print the help" << std::endl;
        std::cout << "-d       print the frames to stdout" << std::endl;
        std::cout << "-l       log the frames in a database" << std::endl;
    }

    int parse_arguments(int argc, char **argv)
    {
        int option;

        display = false;
        log = false;

        while ((option = getopt(argc, argv, ":hdl")) != -1) {
            switch (option) {
            case 'd':
                display = true;

                break;
            case 'h':
                display_help();

                return 1;
            case 'l':
                log = true;

                break;
            case ':':
                std::cout << "a value is required, use -h to print the help"
                    << std::endl;

                return 1;
            case '?':
                std::cout << "unknown option: " << (char) optopt
                    << ", use -h to print the help" << std::endl;

                return 1;
            }
        }

        return 0;
    }

    int init(int argc, char **argv)
    {
        int ret;

        ret = parse_arguments(argc, argv);

        if (ret)
            return 1;

        db = new db_manager;

        db->open();
        db->create_database("modbus");
        db->create_tables();

        // list_interfaces();

        //display_xls_config_file(XLS_CONFIG_FILE_NAME);
        extract_data_from_xls_config_file(XLS_CONFIG_FILE_NAME, devices_map);
        display_devices();

        add_addresses_to_db(db);

        return 0;
    }

    int run()
    {
        pcap_t *pcap_handler;
        struct bpf_program filter;
        char error_buffer[PCAP_ERRBUF_SIZE];
        char const *device = "lo";
        int snapshot_len = 1028;
        int promiscuous = 1;
        int timeout = 1000;
        int res;

        pcap_handler = pcap_open_live(device, snapshot_len, promiscuous,
                                      timeout, error_buffer);

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
    }

    void close()
    {
        db->close();
    }
}

int main(int argc, char **argv)
{
    int ret;

    ret = logger::init(argc, argv);

    if (ret)
        return 0;

    logger::run();
    logger::close();

    return 0;
}
