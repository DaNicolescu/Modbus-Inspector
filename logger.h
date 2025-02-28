#ifndef LOGGER_H
#define LOGGER_H

#include <unordered_map>
#include <string>
#include <pcap.h>
#include <chrono>

#include "db.h"

namespace logger {
    int init(int argc, char **argv);
    int run();
    void close_logger();

    void display_help();
    int parse_arguments(int argc, char **argv);

    void sig_handler(int signum);

    void display_devices();
    void add_addresses_to_db(struct db_manager *db);

    bool modbus_frame_is_query(uint16_t transaction_id);

    struct device_struct *get_device(uint8_t slave_id);

    void handle_read_query(const struct device_struct *dev,
        struct modbus_read_query *read_query, struct modbus_aggregate
        *modbus_aggregated_frame, uint16_t address_offset);
    void handle_read_query(const struct modbus_read_query *read_query,
        const std::string &errors);
    void handle_read_response(const struct device_struct *dev,
        struct modbus_read_response *read_response, struct modbus_aggregate
        *modbus_aggregated_frame);
    void handle_single_write_query(const struct device_struct *dev,
        struct modbus_single_write *single_write_frame, struct modbus_aggregate
        *modbus_aggregated_frame, uint16_t address_offset);
    void handle_single_write_query(const struct modbus_single_write
        *single_write_frame, const std::string &errors);
    void handle_single_write_response(const struct device_struct *dev,
        struct modbus_single_write *single_write_frame,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_read_exception_status_query(struct modbus_generic
        *exception_status_query, struct modbus_aggregate
        *modbus_aggregated_frame);
    void handle_read_exception_status_response(const struct device_struct *dev,
        struct modbus_exception_status_response *exception_status_response,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_diagnostics_query(struct modbus_diagnostics *diagnostics_query,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_diagnostics_response(const struct device_struct *dev,
        struct modbus_diagnostics *diagnostics_response,
        struct modbus_aggregate* modbus_aggregated_frame);
    void handle_fetch_comm_event_counter_query(struct modbus_generic
        *event_counter_query, struct modbus_aggregate *modbus_aggregated_frame);
    void handle_fetch_comm_event_counter_response(const struct device_struct
        *dev, struct modbus_event_counter_response *event_counter_response,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_fetch_comm_event_log_query(struct modbus_generic
        *event_log_query, struct modbus_aggregate *modbus_aggregated_frame);
    void handle_fetch_comm_event_log_response(const struct device_struct *dev,
        struct modbus_event_log_response *event_log_response,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_force_multiple_write_query(const struct device_struct *dev,
        struct modbus_multiple_write_query *multiple_write_query,
        struct modbus_aggregate *modbus_aggregated_frame,
        uint16_t address_offset);
    void handle_force_multiple_write_query(struct modbus_multiple_write_query
        *multiple_write_query, const std::string &errors);
    void handle_force_multiple_write_response(const struct device_struct *dev,
        struct modbus_multiple_write_response *multiple_write_response,
        struct modbus_aggregate *modbus_aggregated_frame,
        uint16_t address_offset);
    void handle_force_multiple_write_response(
        struct modbus_multiple_write_response *multiple_write_response,
        const std::string &errors);
    void handle_report_slave_id_request(struct modbus_generic
        *report_slave_id_request,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_report_slave_id_response(struct device_struct *dev,
        struct modbus_report_slave_id_response *report_slave_id_response,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_mask_write_query(const struct device_struct *dev,
        struct modbus_mask_write *mask_write,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_mask_write_query(const struct modbus_mask_write *mask_write,
        const std::string &errors);
    void handle_mask_write_response(const struct device_struct *dev,
        struct modbus_mask_write *mask_write,
        struct modbus_aggregate *modbus_aggregated_frame);
    void handle_mask_write_response(struct modbus_mask_write *mask_write,
        const std::string &errors);

    void modbus_packet_handler(const uint8_t *payload);

    void inc_duration(std::chrono::duration<double> diff);
};

#endif
