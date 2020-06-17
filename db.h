#ifndef DB_H
#define DB_H

#include <string>

typedef struct st_mysql MYSQL;

struct address_struct;

struct modbus_read_query;
struct modbus_read_response;
struct modbus_single_write;
struct modbus_multiple_write_query;
struct modbus_multiple_write_response;
struct modbus_aggregate;

struct db_manager {
    MYSQL *connection;

    static void display_client_version();
    
    bool open();
    void close();
    bool create_database(std::string db_name);
    bool create_tables();
    bool drop_tables();

    bool add_address(struct address_struct *address, uint8_t slave_id);

    bool add_read_query(struct modbus_read_query *modbus_struct);
    bool add_read_response(struct modbus_read_response *modbus_struct);
    bool add_single_write(struct modbus_single_write *modbus_struct,
                          uint8_t type);
    bool add_multiple_write_query(struct modbus_multiple_write_query
                                  *modbus_struct);
    bool add_multiple_write_response(struct modbus_multiple_write_response
                                     *modbus_struct);

    bool add_display_frame(struct modbus_aggregate *modbus_struct);
};

#endif
