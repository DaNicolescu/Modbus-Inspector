#ifndef DB_H
#define DB_H

#include <string>
#include <thread>

#include "prod_con_queue.h"

#define DISPLAY_FRAME_SEPARATOR     '|'

#define QUERY_FRAME                 0
#define RESPONSE_FRAME              1

typedef struct st_mysql MYSQL;

struct device_struct;
struct address_struct;

struct modbus_generic;
struct modbus_read_query;
struct modbus_read_response;
struct modbus_single_write;
struct modbus_exception_status_response;
struct modbus_diagnostics;
struct modbus_event_counter_response;
struct modbus_event_log_response;
struct modbus_multiple_write_query;
struct modbus_multiple_write_response;
struct modbus_report_slave_id_response;
struct modbus_exception;
struct modbus_aggregate;

struct db_manager {
    MYSQL *connection;
    std::thread db_thread;
    prod_con_queue *db_queue; 

    static void display_client_version();
    static void db_thread_function(struct db_manager *manager);
    
    bool open();
    void close();
    bool create_database(std::string db_name);
    bool create_tables();
    bool drop_tables();

    bool add_address(struct address_struct *address, uint8_t slave_id);

    bool add_modbus_generic(const struct modbus_generic *modbus_struct,
                            uint8_t type);
    bool add_modbus_generic(const struct modbus_generic *modbus_struct,
                            uint8_t type, const std::string &errors);
    bool add_read_query(const struct modbus_read_query *modbus_struct);
    bool add_read_query(const struct modbus_read_query *modbus_struct,
                        const std::string &errors);
    bool add_read_response(const struct modbus_read_response *modbus_struct);
    bool add_single_write(const struct modbus_single_write *modbus_struct,
                          uint8_t type);
    bool add_single_write(const struct modbus_single_write *modbus_struct,
                          uint8_t type, const std::string &errors);
    bool add_exception_status_response(
        const struct modbus_exception_status_response *modbus_struct);
    bool add_diagnostics(const struct modbus_diagnostics *modbus_struct,
                         uint8_t type);
    bool add_event_counter_response(const struct modbus_event_counter_response
                                    *modbus_struct);
    bool add_event_log_response(const struct modbus_event_log_response
                                *modbus_struct);
    bool add_multiple_write_query(const struct modbus_multiple_write_query
                                  *modbus_struct);
    bool add_multiple_write_query(const struct modbus_multiple_write_query
                                  *modbus_struct, const std::string &errors);
    bool add_multiple_write_response(const struct modbus_multiple_write_response
                                     *modbus_struct);
    bool add_multiple_write_response(const struct modbus_multiple_write_response
                                     *modbus_struct, const std::string &errors);
    bool add_report_slave_id_response(
        const struct modbus_report_slave_id_response *modbus_struct);
    bool add_mask_write(const struct modbus_mask_write *mask_write,
                        uint8_t type);
    bool add_mask_write(const struct modbus_mask_write *mask_write,
                        uint8_t type, const std::string &errors);
    bool add_exception(const struct modbus_exception *modbus_struct);

    bool add_display_frame(const std::string &type, const std::string &query,
                           const std::string &response);
    bool add_display_frame(const std::string &type, const std::string &query,
                           const std::string &response,
                           const std::string &aggregated);
    bool add_aggregated_data(int address_id, uint16_t transaction_id,
                             uint8_t slave_id, uint16_t address,
                             uint8_t operation, const std::string &value);
    bool add_aggregated_frame(const struct device_struct *dev,
                              const struct modbus_aggregate *aggregated_frame);
    bool add_aggregated_exception_frame(const struct modbus_aggregate
                                        *aggregated_frame);
};

#endif
