#include <iostream>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>

#include "logger.h"
#include "serial_sniffer.h"
#include "tcp_sniffer.h"
#include "XlsReader.h"
#include "device_struct.h"
#include "modbus.h"
#include "config.h"
#include "utils.h"
#include "db.h"

namespace logger {
    bool display;
    bool log;
    bool timed;
    bool serial;

    // modbus tcp
    std::string interface;

    // modbus serial
    unsigned int baud_rate;
    unsigned int parity_bit;
    unsigned int stop_bits;
    std::string port1;
    std::string port2;

    unsigned int seconds;

    std::unordered_map<uint16_t, struct modbus_aggregate*>
        modbus_aggregated_frames;
    std::unordered_map<uint8_t, struct device_struct*> devices_map;
    struct db_manager *db;

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
        if (log)
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
        if (log)
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
        if (log)
            db->add_read_response(read_response);

        if (display)
            display_modbus_read_response(read_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = read_response;

            if (log)
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
        if (log)
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
        if (log)
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
        if (log)
            db->add_single_write(single_write_frame, RESPONSE_FRAME);

        if (display)
            display_modbus_single_write(single_write_frame, false);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = single_write_frame;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);

            if (display)
                dev->display_addresses(modbus_aggregated_frame);
        }
    }

    void handle_read_exception_status_query(struct modbus_generic
        *exception_status_query, struct modbus_aggregate
        *modbus_aggregated_frame)
    {
        if (log)
            db->add_modbus_generic(exception_status_query, QUERY_FRAME);

        if (display)
            display_modbus_generic(exception_status_query, true);

        modbus_aggregated_frame->function_code =
            exception_status_query->function_code;
        modbus_aggregated_frame->query = exception_status_query;
    }

    void handle_read_exception_status_response(const struct device_struct
        *dev, struct modbus_exception_status_response
        *exception_status_response, struct modbus_aggregate
        *modbus_aggregated_frame)
    {
        if (log)
            db->add_exception_status_response(exception_status_response);

        if (display)
            display_modbus_exception_status_response(exception_status_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = exception_status_response;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_diagnostics_query(struct modbus_diagnostics
        *diagnostics_query, struct modbus_aggregate *modbus_aggregated_frame)
    {
        if (log)
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
        if (log)
            db->add_diagnostics(diagnostics_response, RESPONSE_FRAME);

        if (display)
            display_modbus_diagnostics(diagnostics_response, false);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = diagnostics_response;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_fetch_comm_event_counter_query(struct modbus_generic
        *event_counter_query, struct modbus_aggregate *modbus_aggregated_frame)
    {
        if (log)
            db->add_modbus_generic(event_counter_query, QUERY_FRAME);

        if (display)
            display_modbus_generic(event_counter_query, true);

        modbus_aggregated_frame->function_code =
            event_counter_query->function_code;
        modbus_aggregated_frame->query = event_counter_query;
    }

    void handle_fetch_comm_event_counter_response(const struct device_struct
        *dev, struct modbus_event_counter_response *event_counter_response,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        if (log)
            db->add_event_counter_response(event_counter_response);

        if (display)
            display_modbus_event_counter_response(event_counter_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = event_counter_response;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_fetch_comm_event_log_query(struct modbus_generic
        *event_log_query, struct modbus_aggregate *modbus_aggregated_frame)
    {
        if (log)
            db->add_modbus_generic(event_log_query, QUERY_FRAME);

        if (display)
            display_modbus_generic(event_log_query, true);

        modbus_aggregated_frame->function_code = event_log_query->function_code;
        modbus_aggregated_frame->query = event_log_query;
    }

    void handle_fetch_comm_event_log_response(const struct device_struct
        *dev, struct modbus_event_log_response *event_log_response,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        if (log)
            db->add_event_log_response(event_log_response);

        if (display)
            display_modbus_event_log_response(event_log_response);

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = event_log_response;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_force_multiple_write_query(const struct device_struct *dev,
        struct modbus_multiple_write_query *multiple_write_query,
        struct modbus_aggregate *modbus_aggregated_frame,
        uint16_t address_offset)
    {
        if (log)
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
        if (log)
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
        if (log)
            db->add_multiple_write_response(multiple_write_response);

        if (display) {
            display_modbus_multiple_write_response(multiple_write_response);
            dev->display_addresses(multiple_write_response->starting_address
                + address_offset, multiple_write_response->num_of_points);
        }

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = multiple_write_response;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);

            if (display)
                dev->display_addresses(modbus_aggregated_frame);
        }
    }

    void handle_force_multiple_write_response(
        struct modbus_multiple_write_response *multiple_write_response,
        const std::string &errors)
    {
        if (log)
            db->add_multiple_write_response(multiple_write_response, errors);
    }

    void handle_report_slave_id_request(struct modbus_generic
        *report_slave_id_request, struct modbus_aggregate
        *modbus_aggregated_frame)
    {
        if (log)
            db->add_modbus_generic(report_slave_id_request, QUERY_FRAME);

        if (display)
            display_modbus_generic(report_slave_id_request, true);

        modbus_aggregated_frame->function_code =
            report_slave_id_request->function_code;
        modbus_aggregated_frame->query = report_slave_id_request;
    }

    void handle_report_slave_id_response(struct device_struct *dev,
        struct modbus_report_slave_id_response *report_slave_id_response,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        if (log)
            db->add_report_slave_id_response(report_slave_id_response);

        if (display)
            display_modbus_report_slave_id_response(report_slave_id_response);

        modbus_aggregated_frame->response = report_slave_id_response;

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = report_slave_id_response;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);
        }
    }

    void handle_mask_write_query(const struct device_struct *dev,
        struct modbus_mask_write *mask_write,
        struct modbus_aggregate *modbus_aggregated_frame)
    {
        if (log)
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
        if (log)
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
        if (log)
            db->add_mask_write(mask_write, RESPONSE_FRAME);

        if (display) {
            display_modbus_mask_write(mask_write, false);
            dev->display_addresses(mask_write->address + HLD_REGS_OFFSET, 1);
        }

        if (modbus_aggregated_frame->query != NULL) {
            modbus_aggregated_frame->response = mask_write;

            if (log)
                db->add_aggregated_frame(dev, modbus_aggregated_frame);

            if (display)
                dev->display_addresses(modbus_aggregated_frame);
        }
    }

    void handle_mask_write_response(struct modbus_mask_write *mask_write,
        const std::string &errors)
    {
        if (log)
            db->add_mask_write(mask_write, RESPONSE_FRAME, errors);
    }

    void modbus_packet_handler(const uint8_t *payload)
    {
        struct modbus_generic *modbus_generic;
        struct modbus_read_query *read_query;
        struct modbus_read_response *read_response;
        struct modbus_single_write *single_write_packet;
        struct modbus_generic *exception_status_query;
        struct modbus_exception_status_response *exception_status_response;
        struct modbus_diagnostics *diagnostics_query;
        struct modbus_diagnostics *diagnostics_response;
        struct modbus_generic *event_counter_query;
        struct modbus_event_counter_response *event_counter_response;
        struct modbus_generic *event_log_query;
        struct modbus_event_log_response *event_log_response;
        struct modbus_multiple_write_query *multiple_write_query;
        struct modbus_multiple_write_response *multiple_write_response;
        struct modbus_aggregate *modbus_aggregated_frame;
        struct modbus_generic *report_slave_id_query;
        struct modbus_report_slave_id_response *report_slave_id_response;
        struct modbus_mask_write *mask_write;
        struct modbus_exception *exception;
        struct device_struct *dev;
        struct address_struct *addr;
        bool query_frame;
        std::string errors;
        bool valid_frame;

        modbus_generic = get_modbus_generic(payload);

        if (modbus_generic->protocol_id != 0 || modbus_generic->length > 256)
            return;

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

            if (log)
                db->add_modbus_generic(modbus_generic, 0, errors);

            std::cout << errors << std::endl;
            std::cout << std::endl;

            return;
        }

        if (modbus_generic->function_code > 0x80) {
            exception = get_modbus_exception(payload);

            if (log)
                db->add_exception(exception);

            if (display)
                display_modbus_exception(exception);

            if (modbus_aggregated_frame->query != NULL) {
                modbus_aggregated_frame->function_code += 0x80;
                modbus_aggregated_frame->response = exception;

                if (log)
                    db->add_aggregated_exception_frame(modbus_aggregated_frame);
            }

            return;
        }

        if (!dev->supported_function(modbus_generic->function_code)) {
            errors = "Function code "
                + std::to_string(modbus_generic->function_code)
                + " not supported";

            if (log)
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
                exception_status_query = get_modbus_generic(payload);

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
                event_counter_query = get_modbus_generic(payload);

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
                event_log_query = get_modbus_generic(payload);

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

                valid_frame = dev->valid_write_hld_regs_addresses(
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
                report_slave_id_query = get_modbus_generic(payload);

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
        std::cout << "MODBUS Logger" << std::endl;
        std::cout << "-h                                    print the help"
            << std::endl;
        std::cout << "-i INT_NAME                           capture MODBUS TCP "
            << "frames on the INT_NAME interface" << std::endl;
        std::cout << "-s BAUD_RATE PARITY_OPTION STOP_BITS  capture MODBUS RTU "
            << "frames (PARITY_OPTION: 0 for no parity, 1 for odd parity and 2 "
            << "for even parity; STOP_BITS: 1 or 2)" << std::endl;
        std::cout << "-p PORT1 PORT2                        use the specified "
            << "serial ports (PORT1 is used to sniff the incoming Master "
            << "queries and PORT2 is used to sniff the incoming Slave "
            << "responses)" << std::endl;
        std::cout << "-d                                    print the frames "
            << "to stdout" << std::endl;
        std::cout << "-l DB_NAME                            create and log the "
            << "frames in a database" << std::endl;
        std::cout << "-t SECONDS                            run the logger for "
            << "a specified amount of time (by default the program runs "
            << "indefinitely and can be stopped using the SIGINT signal)"
            << std::endl;

        std::cout << std::endl;
        std::cout << "Available Interfaces" << std::endl;

        tcp_sniffer::list_interfaces();
    }

    int parse_arguments(int argc, char **argv)
    {
        int option;

        display = false;
        log = false;
        timed = false;
        serial = false;

        while ((option = getopt(argc, argv, ":hdl:i:t:s:p:")) != -1) {
            switch (option) {
            case 'd':
                display = true;

                break;
            case 'h':
                display_help();

                return 1;
            case 'i':
                interface = std::string(optarg);

                break;
            case 'l':
                log = true;

                db = new db_manager;

                db->open();
                db->create_database(std::string(optarg));
                db->create_tables();

                break;
            case 'p':
                port1 = std::string(optarg);

                if (optind < argc && *argv[optind] != '-') {
                    port2 = std::string(argv[optind]);

                    optind++;
                } else {
                    std::cout << "-p option requires two arguments"
                        << std::endl;

                    display_help();

                    return 1;
                }

                break;
            case 's':
                serial = true;

                sscanf(optarg, "%u", &baud_rate);

                if (optind < argc && *argv[optind] != '-'){
                    sscanf(argv[optind], "%u", &parity_bit);

                    optind++;
                } else {
                    std::cout << "-s option requires three arguments"
                        << std::endl;

                    display_help();

                    return 1;
                }

                if (optind < argc && *argv[optind] != '-'){
                    sscanf(argv[optind], "%u", &stop_bits);

                    optind++;
                } else {
                    std::cout << "-s option requires three arguments"
                        << std::endl;

                    display_help();

                    return 1;
                }

                break;
            case 't':
                timed = true;

                sscanf(optarg, "%u", &seconds);

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

    void sig_handler(int signum)
    {
        std::cout << std::endl;
        std::cout << "Terminating program..." << std::endl;

        close_logger();

        exit(0);
    }

    int init(int argc, char **argv)
    {
        int ret;

        ret = parse_arguments(argc, argv);

        if (ret)
            return 1;

        //display_xls_config_file(XLS_CONFIG_FILE_NAME);
        extract_data_from_xls_config_file(XLS_CONFIG_FILE_NAME, devices_map);
        display_devices();

        if (log)
            add_addresses_to_db(db);

        if (serial) {
            //serial_sniffer::init(port1, port2, B19200, CS8,
            //    NO_PARITY, ONE_STOP_BIT);
            serial_sniffer::init(port1, port2, baud_rate, CS8, parity_bit,
                stop_bits);
        } else {
            tcp_sniffer::init(interface);
        }

        return 0;
    }

    int run()
    {
        signal(SIGINT, sig_handler);

        if (timed) {
            signal(SIGALRM, sig_handler);

            alarm(seconds);
        }

        if (serial)
            return serial_sniffer::run();

        return tcp_sniffer::run();
    }

    void close_logger()
    {
        if (serial)
            serial_sniffer::close_sniffer();
        else
            tcp_sniffer::close_sniffer();

        if (log)
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
    logger::close_logger();

    return 0;
}
