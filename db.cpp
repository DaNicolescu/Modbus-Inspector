#include <iostream>
#include <string.h>
#include <unordered_map>
#include <mysql.h>

#include "db.h"
#include "device_struct.h"
#include "modbus.h"
#include "utils.h"
#include "config.h"

void db_manager::display_client_version()
{
    std::cout << "The DB client version is: " << mysql_get_client_info()
        << std::endl;
}

void db_manager::db_thread_function(struct db_manager *manager)
{
    while (true) {
        std::string query = manager->db_queue->consume();

        if (query == "end")
            break;

        if (mysql_query(manager->connection, query.c_str())) {
            std::cout << mysql_error(manager->connection) << std::endl;
            mysql_close(manager->connection);

            return;
        }
    }

    while (!manager->db_queue->queue.empty()){
        std::string query = manager->db_queue->queue.front();

        if (mysql_query(manager->connection, query.c_str())) {
            std::cout << mysql_error(manager->connection) << std::endl;
            mysql_close(manager->connection);

            return;
        }

        manager->db_queue->queue.pop();
    }
}

bool db_manager::open()
{
    this->connection = mysql_init(NULL);

    if (!this->connection) {
        std::cout << mysql_error(this->connection);

        return false;
    }

    if (!mysql_real_connect(this->connection, "127.0.0.1", "root", NULL,
        NULL, 3306, NULL, 0)) {

        std::cout << mysql_error(this->connection) << std::endl;

        mysql_close(this->connection);

        return false;
    }

    this->db_queue = new prod_con_queue(3000);
    this->db_thread = std::thread(db_manager::db_thread_function, this);

    return true;
}

void db_manager::close()
{
    this->db_queue->add("end");
    this->db_thread.join();

    mysql_close(this->connection);
}

bool db_manager::create_database(std::string db_name)
{
    std::string query;

    query = "CREATE DATABASE IF NOT EXISTS " + db_name;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    query = "USE " + db_name;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}

bool db_manager::create_tables()
{
    std::string query = "CREATE TABLE IF NOT EXISTS `frames` ("
                        "`id` INTEGER AUTO_INCREMENT PRIMARY KEY,"
                        "`type` TINYINT,"
                        "`transaction_id` SMALLINT UNSIGNED,"
                        "`protocol_id` SMALLINT UNSIGNED,"
                        "`length` SMALLINT UNSIGNED,"
                        "`slave_id` TINYINT UNSIGNED,"
                        "`function_code` TINYINT UNSIGNED,"
                        "`starting_address` SMALLINT UNSIGNED,"
                        "`num_of_points` SMALLINT UNSIGNED,"
                        "`byte_count` TINYINT UNSIGNED,"
                        "`value` VARCHAR(10),"
                        "`data` TEXT,"
                        "`errors` TEXT)";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    query = "CREATE TABLE IF NOT EXISTS `addresses` ("
            "`id` INTEGER AUTO_INCREMENT PRIMARY KEY,"
            "`slave_id` TINYINT UNSIGNED,"
            "`address` SMALLINT UNSIGNED,"
            "`description` TEXT,"
            "`notes` TEXT)";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    query = "CREATE TABLE IF NOT EXISTS `aggregated_data` ("
            "`id` INTEGER AUTO_INCREMENT PRIMARY KEY,"
            "`address_id` INTEGER,"
            "`transaction_id` SMALLINT UNSIGNED,"
            "`slave_id` TINYINT UNSIGNED,"
            "`address` SMALLINT UNSIGNED,"
            "`operation` TINYINT,"
            "`value` VARCHAR(10),"
            "CONSTRAINT `fk_address_id`"
                "FOREIGN KEY (address_id) REFERENCES addresses (id)"
                "ON DELETE CASCADE"
            ")";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    query = "CREATE TABLE IF NOT EXISTS `display_frames` ("
            "`id` INTEGER AUTO_INCREMENT PRIMARY KEY,"
            "`type` TEXT,"
            "`request` TEXT,"
            "`response` TEXT,"
            "`aggregated` TEXT)";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}

bool db_manager::drop_tables()
{
    std::string query = "DROP TABLE `frames`";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    query = "DROP TABLE `aggregated_data`";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    query = "DROP TABLE `addresses`";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    query = "DROP TABLE `display_frames`";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}

bool db_manager::add_address(struct address_struct *address, uint8_t slave_id)
{
    std::string query = "INSERT INTO `addresses`(slave_id, address, "
                        "description, notes) VALUES("
                        + std::to_string(slave_id) + ", "
                        + std::to_string(address->address) + ", '"
                        + address->description + "', '"
                        + address->notes + "')";

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    address->db_id = mysql_insert_id(this->connection);

    return true;
}

bool db_manager::add_modbus_generic(const struct modbus_generic
                                    *modbus_struct, uint8_t type)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code) VALUES("
                        + std::to_string(type) + ", "
                        + std::to_string(modbus_struct->transaction_id) + ", "
                        + std::to_string(modbus_struct->protocol_id) + ", "
                        + std::to_string(modbus_struct->length) + ", "
                        + std::to_string(modbus_struct->unit_id) + ", "
                        + std::to_string(modbus_struct->function_code) + ")";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_modbus_generic(const struct modbus_generic
                                    *modbus_struct, uint8_t type,
                                    const std::string &errors)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, errors) "
                        "VALUES(" + std::to_string(type) + ", "
                        + std::to_string(modbus_struct->transaction_id) + ", "
                        + std::to_string(modbus_struct->protocol_id) + ", "
                        + std::to_string(modbus_struct->length) + ", "
                        + std::to_string(modbus_struct->unit_id) + ", "
                        + std::to_string(modbus_struct->function_code) + ", '"
                        + errors + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_read_query(const struct modbus_read_query *modbus_struct)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, num_of_points) VALUES(0, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->starting_address) + ", "
                        + std::to_string(modbus_struct->num_of_points) + ")";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_read_query(const struct modbus_read_query *modbus_struct,
                                const std::string &errors)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, num_of_points, errors) VALUES(0, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->starting_address) + ", "
                        + std::to_string(modbus_struct->num_of_points) + ", '"
                        + errors + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_read_response(
    const struct modbus_read_response *modbus_struct)
{
    std::string response_data;
    uint8_t byte_count;
    uint8_t function_code;

    byte_count = modbus_struct->byte_count;
    function_code = modbus_struct->generic_header.function_code;

    if (function_code == READ_COIL_STATUS
        || function_code == READ_INPUT_STATUS) {
        if (byte_count > 0)
            response_data = byte_to_binary_string(modbus_struct->data[0]);

        for (uint8_t i = 1; i < byte_count; i++) {
            response_data += ", "
                + byte_to_binary_string(modbus_struct->data[i]);
        }
    } else if (function_code == READ_HOLDING_REGISTERS
               || function_code == READ_INPUT_REGISTERS) {
        if (byte_count > 1) {
            response_data = std::to_string(bytes_to_int(modbus_struct->data[0],
                                           modbus_struct->data[1]));
        }

        for (uint8_t i = 2; i < byte_count; i += 2) {
            response_data += ", " + std::to_string(bytes_to_int(
                    modbus_struct->data[i], modbus_struct->data[i + 1]));
        }
    }

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "byte_count, data) VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->byte_count) + ", '"
                        + response_data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_single_write(
    const struct modbus_single_write *modbus_struct, uint8_t type)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, value) VALUES("
                        + std::to_string(type) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->address) + ", "
                        + std::to_string(modbus_struct->value) + ")";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_single_write(
    const struct modbus_single_write *modbus_struct, uint8_t type,
    const std::string &errors)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, value, errors) VALUES("
                        + std::to_string(type) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->address) + ", "
                        + std::to_string(modbus_struct->value) + ", '"
                        + errors + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_exception_status_response(
    const struct modbus_exception_status_response *modbus_struct)
{
    std::string response_data;

    response_data = byte_to_binary_string(modbus_struct->coil_data);

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, data)"
                        " VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", '"
                        + response_data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_diagnostics(const struct modbus_diagnostics *modbus_struct,
                                 uint8_t type)
{
    std::string data = std::to_string(modbus_struct->subfunction) + ", "
        + std::to_string(modbus_struct->data);

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, data)"
                        " VALUES(" + std::to_string(type) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", '"
                        + data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_event_counter_response(
    const struct modbus_event_counter_response *modbus_struct)
{
    std::string response_data;

    response_data = std::to_string(modbus_struct->status) + ", "
        + std::to_string(modbus_struct->event_count);

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, data)"
                        " VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", '"
                        + response_data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_event_log_response(const struct modbus_event_log_response
                                        *modbus_struct)
{
    std::string response_data;

    response_data = std::to_string(modbus_struct->status) + ", "
        + std::to_string(modbus_struct->event_count) + ", "
        + std::to_string(modbus_struct->message_count) + ", "
        + std::to_string(modbus_struct->event0) + ", "
        + std::to_string(modbus_struct->event1);

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "byte_count, data) VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->byte_count) + ", '"
                        + response_data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_multiple_write_query(
    const struct modbus_multiple_write_query *modbus_struct)
{
    std::string request_data;
    uint8_t byte_count;
    uint8_t function_code;

    byte_count = modbus_struct->byte_count;
    function_code = modbus_struct->generic_header.function_code;

    if (function_code == FORCE_MULTIPLE_COILS) {
        if (byte_count > 0)
            request_data = byte_to_binary_string(modbus_struct->data[0]);

        for (uint8_t i = 1; i < byte_count; i++) {
            request_data += ", "
                + byte_to_binary_string(modbus_struct->data[i]);
        }
    } else if (function_code == PRESET_MULTIPLE_REGISTERS) {
        if (byte_count > 1) {
            request_data = std::to_string(bytes_to_int(modbus_struct->data[0],
                                          modbus_struct->data[1]));
        }

        for (uint8_t i = 2; i < byte_count; i += 2) {
            request_data += ", " + std::to_string(bytes_to_int(
                    modbus_struct->data[i], modbus_struct->data[i + 1]));
        }
    }

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, num_of_points, byte_count, data) "
                        "VALUES(0, " + std::to_string(
                                modbus_struct->generic_header.transaction_id)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->starting_address) + ", "
                        + std::to_string(modbus_struct->num_of_points) + ", "
                        + std::to_string(modbus_struct->byte_count) + ", '"
                        + request_data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_multiple_write_query(
    const struct modbus_multiple_write_query *modbus_struct,
    const std::string &errors)
{
    std::string request_data;
    uint8_t byte_count;
    uint8_t function_code;

    byte_count = modbus_struct->byte_count;
    function_code = modbus_struct->generic_header.function_code;

    if (function_code == FORCE_MULTIPLE_COILS) {
        if (byte_count > 0)
            request_data = byte_to_binary_string(modbus_struct->data[0]);

        for (uint8_t i = 1; i < byte_count; i++) {
            request_data += ", "
                + byte_to_binary_string(modbus_struct->data[i]);
        }
    } else if (function_code == PRESET_MULTIPLE_REGISTERS) {
        if (byte_count > 1) {
            request_data = std::to_string(bytes_to_int(modbus_struct->data[0],
                                          modbus_struct->data[1]));
        }

        for (uint8_t i = 2; i < byte_count; i += 2) {
            request_data += ", " + std::to_string(bytes_to_int(
                    modbus_struct->data[i], modbus_struct->data[i + 1]));
        }
    }

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, num_of_points, byte_count, data, "
                        "errors) VALUES(0, " + std::to_string(
                                modbus_struct->generic_header.transaction_id)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->starting_address) + ", "
                        + std::to_string(modbus_struct->num_of_points) + ", "
                        + std::to_string(modbus_struct->byte_count) + ", '"
                        + request_data + "', '" + errors  + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_multiple_write_response(
    const struct modbus_multiple_write_response *modbus_struct)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, num_of_points) VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->starting_address) + ", "
                        + std::to_string(modbus_struct->num_of_points) + ")";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_multiple_write_response(
    const struct modbus_multiple_write_response *modbus_struct,
    const std::string &errors)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "starting_address, num_of_points, errors) VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->starting_address) + ", "
                        + std::to_string(modbus_struct->num_of_points) + ", '"
                        + errors + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_report_slave_id_response(
    const struct modbus_report_slave_id_response *modbus_struct)
{
    std::string response_data;
    uint8_t byte_count;

    byte_count = modbus_struct->byte_count - 2;

    response_data = std::to_string(modbus_struct->slave_id) + ", "
        + std::to_string(modbus_struct->run_indicator_status);

    for (uint8_t i = 0; i < byte_count; i++) {
        response_data += ", "
            + std::to_string(modbus_struct->additional_data[i]);
    }

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "byte_count, data) VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", "
                        + std::to_string(modbus_struct->byte_count) + ", '"
                        + response_data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_mask_write(const struct modbus_mask_write *modbus_struct,
                                uint8_t type)
{
    std::string data;

    data = byte_to_binary_string(modbus_struct->and_mask) + ", "
        + byte_to_binary_string(modbus_struct->or_mask);

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "data) VALUES(" + std::to_string(type) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", '"
                        + data + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_mask_write(const struct modbus_mask_write *modbus_struct,
                                uint8_t type, const std::string &errors)
{
    std::string data;

    data = byte_to_binary_string(modbus_struct->and_mask) + ", "
        + byte_to_binary_string(modbus_struct->or_mask);

    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "data, errors) VALUES(" + std::to_string(type) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code) + ", '"
                        + data + "', '" + errors + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_exception(const struct modbus_exception *modbus_struct)
{
    std::string query = "INSERT INTO `frames`(type, transaction_id, "
                        "protocol_id, length, slave_id, function_code, "
                        "data) VALUES(1, "
                        + std::to_string(
                            modbus_struct->generic_header.transaction_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.protocol_id) + ", "
                        + std::to_string(modbus_struct->generic_header.length)
                        + ", " + std::to_string(
                            modbus_struct->generic_header.unit_id) + ", "
                        + std::to_string(
                            modbus_struct->generic_header.function_code)
                        +  ", '" + std::to_string(modbus_struct->exception_code)
                        + "')";

    this->db_queue->add(query);

    return true;
}

bool db_manager::add_display_frame(const std::string &type,
                                   const std::string &query,
                                   const std::string &response)
{
    std::string db_query = "INSERT INTO `display_frames`(type, request, "
                           "response) VALUES('" + type + "', '" + query
                           + "', '" + response + "')";

    this->db_queue->add(db_query);

    return true;
}

bool db_manager::add_display_frame(const std::string &type,
                                   const std::string &query,
                                   const std::string &response,
                                   const std::string &aggregated)
{
    std::string db_query = "INSERT INTO `display_frames`(type, request, "
                           "response, aggregated) VALUES('" + type + "', '"
                           + query + "', '" + response + "', '" + aggregated
                           + "')";

    this->db_queue->add(db_query);

    return true;
}

bool db_manager::add_aggregated_data(int address_id, uint16_t transaction_id,
                         uint8_t slave_id, uint16_t address, uint8_t operation,
                         const std::string &value)
{
    std::string db_query = "INSERT INTO `aggregated_data`(address_id, "
                           "transaction_id, slave_id, address, operation, "
                           "value) VALUES(" + std::to_string(address_id) + ", "
                           + std::to_string(transaction_id) + ", "
                           + std::to_string(slave_id) + ", "
                           + std::to_string(address) + ", "
                           + std::to_string(operation) + ", '"
                           + value + "')";

    this->db_queue->add(db_query);

    return true;
}

bool db_manager::add_aggregated_frame(const struct device_struct *dev,
    const struct modbus_aggregate *aggregated_frame)
{
    struct address_struct *addr_data;
    struct modbus_read_query *read_query;
    struct modbus_read_response *read_response;
    struct modbus_single_write *single_write_query;
    struct modbus_single_write *single_write_response;
    struct modbus_generic *exception_status_request;
    struct modbus_exception_status_response *exception_status_response;
    struct modbus_diagnostics *diagnostics_query;
    struct modbus_diagnostics *diagnostics_response;
    struct modbus_generic *event_counter_request;
    struct modbus_event_counter_response *event_counter_response;
    struct modbus_generic *event_log_request;
    struct modbus_event_log_response *event_log_response;
    struct modbus_multiple_write_query *multiple_write_query;
    struct modbus_multiple_write_response *multiple_write_response;
    struct modbus_generic *report_slave_id_request;
    struct modbus_report_slave_id_response *report_slave_id_response;
    struct modbus_mask_write *mask_write_query;
    struct modbus_mask_write *mask_write_response;
    std::string type;
    std::string query;
    std::string response;
    std::string aggregated;
    uint16_t address;
    uint16_t last_address;
    uint16_t num_of_points;
    std::string binary_string;
    std::string data_string;
    uint8_t i;
    uint8_t data_index;
    uint16_t transaction_id;
    uint8_t slave_id;

    switch (aggregated_frame->function_code) {
    case READ_COIL_STATUS:
        type = "READ COIL STATUS";

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        query = get_modbus_read_query_string(read_query,
                                             DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_read_response_string(read_response,
            DISPLAY_FRAME_SEPARATOR) + DISPLAY_FRAME_SEPARATOR + "data: ";
        aggregated = "";

        transaction_id = read_query->generic_header.transaction_id;
        slave_id = read_query->generic_header.unit_id;

        address = read_query->starting_address + COILS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        i = 0;
        data_index = 0;
        binary_string = byte_to_binary_string(read_response->data[data_index]);
        response += binary_string;

        for (; address <= last_address; address++) {
            if (i == 8) {
                i = 0;
                data_index++;
                binary_string = byte_to_binary_string(
                    read_response->data[data_index]);
                response = response + ", " + binary_string;
            }

            addr_data = dev->addresses_map.find(address)->second;
            aggregated = aggregated + "address: " + std::to_string(address)
                + " (" + addr_data->description + ") reading is "
                + binary_string[i] + DISPLAY_FRAME_SEPARATOR + "notes: "
                + addr_data->notes + DISPLAY_FRAME_SEPARATOR;

            add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
                                address, 0, std::string(1, binary_string[i]));

            i++;
        }

        add_display_frame(type, query, response, aggregated);

        break;
    case READ_INPUT_STATUS:
        type = "READ INPUT STATUS";

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        query = get_modbus_read_query_string(read_query,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_read_response_string(read_response,
            DISPLAY_FRAME_SEPARATOR) + DISPLAY_FRAME_SEPARATOR + "data: ";
        aggregated = "";

        transaction_id = read_query->generic_header.transaction_id;
        slave_id = read_query->generic_header.unit_id;

        address = read_query->starting_address + INPUTS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        i = 0;
        data_index = 0;
        binary_string = byte_to_binary_string(read_response->data[data_index]);
        response = response + binary_string;

        for (; address <= last_address; address++) {
            if (i == 8) {
                i = 0;
                data_index++;
                binary_string = byte_to_binary_string(
                    read_response->data[data_index]);
                response = response + ", " + binary_string;
            }

            addr_data = dev->addresses_map.find(address)->second;
            aggregated = aggregated + "address: " + std::to_string(address)
                + " (" + addr_data->description + ") reading is "
                + binary_string[i] + DISPLAY_FRAME_SEPARATOR + "notes: "
                + addr_data->notes + DISPLAY_FRAME_SEPARATOR;

            add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
                                address, 0, std::string(1, binary_string[i]));

            i++;
        }

        add_display_frame(type, query, response, aggregated);

        break;
    case READ_HOLDING_REGISTERS:
        type = "READ HOLDING REGISTERS";

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        query = get_modbus_read_query_string(read_query,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_read_response_string(read_response,
            DISPLAY_FRAME_SEPARATOR) + DISPLAY_FRAME_SEPARATOR + "data: ";
        aggregated = "";

        transaction_id = read_query->generic_header.transaction_id;
        slave_id = read_query->generic_header.unit_id;

        address = read_query->starting_address + HLD_REGS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        data_index = 0;

        for (; address <= last_address; address++) {

            addr_data = dev->addresses_map.find(address)->second;
            aggregated = aggregated + "address: " + std::to_string(address)
                + " (" + addr_data->description + ") reading is ";

            if (addr_data->type == XLS_FLOAT_TYPE) {
                data_string = std::to_string(bytes_to_float(
                        read_response->data[data_index],
                        read_response->data[data_index + 1]));
                response = response + data_string + ", ";
                aggregated = aggregated + data_string;
            } else {
                data_string = std::to_string(
                    bytes_to_int(read_response->data[data_index],
                    read_response->data[data_index + 1]));
                response = response + data_string + ", ";
                aggregated = aggregated + data_string;
            }

            aggregated = aggregated + DISPLAY_FRAME_SEPARATOR + "notes: "
                + addr_data->notes + DISPLAY_FRAME_SEPARATOR;

            add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
                                address, 0, data_string);

            data_index += 2;
        }

        add_display_frame(type, query, response, aggregated);

        break;
    case READ_INPUT_REGISTERS:
        type = "READ INPUT REGISTERS";

        read_query = (struct modbus_read_query*) aggregated_frame->query;
        read_response = (struct modbus_read_response*)
            aggregated_frame->response;

        query = get_modbus_read_query_string(read_query,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_read_response_string(read_response,
            DISPLAY_FRAME_SEPARATOR) + DISPLAY_FRAME_SEPARATOR + "data: ";
        aggregated = "";

        transaction_id = read_query->generic_header.transaction_id;
        slave_id = read_query->generic_header.unit_id;

        address = read_query->starting_address + INPUT_REGS_OFFSET;
        last_address = address + read_query->num_of_points - 1;

        data_index = 0;

        for (; address <= last_address; address++) {

            addr_data = dev->addresses_map.find(address)->second;
            aggregated = aggregated + "address: " + std::to_string(address)
                + " (" + addr_data->description + ") reading is ";

            if (addr_data->type == XLS_FLOAT_TYPE) {
                data_string = std::to_string(bytes_to_float(
                        read_response->data[data_index],
                        read_response->data[data_index + 1]));
                response = response + data_string + ", ";
                aggregated = aggregated + data_string;
            } else {
                data_string = std::to_string(
                    bytes_to_int(read_response->data[data_index],
                    read_response->data[data_index + 1]));
                response = response + data_string + ", ";
                aggregated = aggregated + data_string;
            }

            aggregated = aggregated + DISPLAY_FRAME_SEPARATOR + "notes: "
                + addr_data->notes + DISPLAY_FRAME_SEPARATOR;

            add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
                address, 0, data_string);

            data_index += 2;
        }

        add_display_frame(type, query, response, aggregated);

        break;
    case FORCE_SINGLE_COIL:
        type = "FORCE SINGLE COIL";

        single_write_query = (struct modbus_single_write*)
            aggregated_frame->query;
        single_write_response = (struct modbus_single_write*)
            aggregated_frame->response;

        query = get_modbus_single_write_string(single_write_query,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_single_write_string(single_write_response,
            DISPLAY_FRAME_SEPARATOR) + DISPLAY_FRAME_SEPARATOR + "data: ";

        transaction_id = single_write_query->generic_header.transaction_id;
        slave_id = single_write_query->generic_header.unit_id;

        address = single_write_query->address + COILS_OFFSET;

        addr_data = dev->addresses_map.find(address)->second;

        response = response + std::to_string(single_write_query->value);

        aggregated = "address: " + std::to_string(address) + " ("
            + addr_data->description + ") was set to "
            + std::to_string(single_write_query->value);

        aggregated = aggregated + DISPLAY_FRAME_SEPARATOR + "notes: "
            + addr_data->notes;

        add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
            address, 1, std::to_string(single_write_query->value));

        add_display_frame(type, query, response, aggregated);

        break;
    case PRESET_SINGLE_REGISTER:
        type = "PRESET SINGLE REGISTER";

        single_write_query = (struct modbus_single_write*)
            aggregated_frame->query;
        single_write_response = (struct modbus_single_write*)
            aggregated_frame->response;

        query = get_modbus_single_write_string(single_write_query,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_single_write_string(single_write_response,
            DISPLAY_FRAME_SEPARATOR) + DISPLAY_FRAME_SEPARATOR + "data: ";

        transaction_id = single_write_query->generic_header.transaction_id;
        slave_id = single_write_query->generic_header.unit_id;

        address = single_write_query->address + HLD_REGS_OFFSET;

        addr_data = dev->addresses_map.find(address)->second;

        aggregated = "address: " + std::to_string(address) + " ("
            + addr_data->description + ") was set to ";

        if (addr_data->type == XLS_FLOAT_TYPE) {
            data_string = std::to_string(float(single_write_query->value));
            response = response + data_string;
            aggregated = aggregated + data_string;
        } else {
            data_string = std::to_string(single_write_query->value);
            response = response + data_string;
            aggregated = aggregated + data_string;
        }

        aggregated = aggregated + DISPLAY_FRAME_SEPARATOR + "notes: "
            + addr_data->notes;

        add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
            address, 1, std::to_string(single_write_query->value));

        add_display_frame(type, query, response, aggregated);

        break;
    case READ_EXCEPTION_STATUS:
        type = "READ EXCEPTION STATUS";

        exception_status_request = (struct modbus_generic*)
            aggregated_frame->query;
        exception_status_response = (struct modbus_exception_status_response*)
            aggregated_frame->response;

        query = get_modbus_generic_string(exception_status_request,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_exception_status_response_string(
            exception_status_response, DISPLAY_FRAME_SEPARATOR);

        add_display_frame(type, query, response);

        break;
    case DIAGNOSTICS:
        type = "DIAGNOSTICS";

        diagnostics_query = (struct modbus_diagnostics*)
            aggregated_frame->query;
        diagnostics_response = (struct modbus_diagnostics*)
            aggregated_frame->response;

        query = get_modbus_diagnostics_string(diagnostics_query,
            DISPLAY_FRAME_SEPARATOR);

        response = get_modbus_diagnostics_string(diagnostics_response,
            DISPLAY_FRAME_SEPARATOR);

        add_display_frame(type, query, response);

        break;
    case FETCH_COMM_EVENT_COUNTER:
        type = "FETCH COMM EVENT COUNTER";

        event_counter_request = (struct modbus_generic*)
            aggregated_frame->query;
        event_counter_response = (struct modbus_event_counter_response*)
            aggregated_frame->response;

        query = get_modbus_generic_string(event_counter_request,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_event_counter_response_string(
            event_counter_response, DISPLAY_FRAME_SEPARATOR);

        add_display_frame(type, query, response);

        break;
    case FETCH_COMM_EVENT_LOG:
        type = "FETCH COMM EVENT LOG";

        event_log_request = (struct modbus_generic*)
            aggregated_frame->query;
        event_log_response = (struct modbus_event_log_response*)
            aggregated_frame->response;

        query = get_modbus_generic_string(event_log_request,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_event_log_response_string(event_log_response,
            DISPLAY_FRAME_SEPARATOR);

        add_display_frame(type, query, response);

        break;
    case FORCE_MULTIPLE_COILS:
        type = "FORCE MULTIPLE COILS";

        multiple_write_query = (struct modbus_multiple_write_query*)
            aggregated_frame->query;
        multiple_write_response = (struct modbus_multiple_write_response*)
            aggregated_frame->response;

        query = get_modbus_multiple_write_query_string(multiple_write_query,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_multiple_write_response_string(
            multiple_write_response, DISPLAY_FRAME_SEPARATOR)
            + DISPLAY_FRAME_SEPARATOR + "data: ";
        aggregated = "";

        transaction_id = multiple_write_query->generic_header.transaction_id;
        slave_id = multiple_write_query->generic_header.unit_id;

        address = multiple_write_query->starting_address + COILS_OFFSET;
        last_address = address + multiple_write_query->num_of_points - 1;

        i = 0;
        data_index = 0;
        binary_string = byte_to_binary_string(
            multiple_write_query->data[data_index]);
        response = response + binary_string;

        for (; address <= last_address; address++) {
            if (i == 8) {
                i = 0;
                data_index++;
                binary_string = byte_to_binary_string(
                    multiple_write_query->data[data_index]);
                response = response + ", " + binary_string;
            }

            addr_data = dev->addresses_map.find(address)->second;
            aggregated = aggregated + "address: " + std::to_string(address)
                + " (" + addr_data->description + ") was set to "
                + binary_string[i] + DISPLAY_FRAME_SEPARATOR + "notes: "
                + addr_data->notes;

            add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
                address, 1, std::string(1, binary_string[i]));

            i++;
        }

        add_display_frame(type, query, response, aggregated);

        break;
    case PRESET_MULTIPLE_REGISTERS:
        type = "PRESET MULTIPLE REGISTERS";

        multiple_write_query = (struct modbus_multiple_write_query*)
            aggregated_frame->query;
        multiple_write_response = (struct modbus_multiple_write_response*)
            aggregated_frame->response;

        query = get_modbus_multiple_write_query_string(multiple_write_query,
            DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_multiple_write_response_string(
            multiple_write_response, DISPLAY_FRAME_SEPARATOR)
            + DISPLAY_FRAME_SEPARATOR + "data: ";
        aggregated = "";

        transaction_id = multiple_write_query->generic_header.transaction_id;
        slave_id = multiple_write_query->generic_header.unit_id;

        address = multiple_write_query->starting_address + HLD_REGS_OFFSET;
        last_address = address + multiple_write_query->num_of_points - 1;

        data_index = 0;

        for (; address <= last_address; address++) {

            addr_data = dev->addresses_map.find(address)->second;
            aggregated = aggregated + "address: " + std::to_string(address)
                + " (" + addr_data->description + ") was set to ";

            if (addr_data->type == XLS_FLOAT_TYPE) {
                data_string = std::to_string(bytes_to_float(
                    multiple_write_query->data[data_index],
                    multiple_write_query->data[data_index + 1]));
                response = response + data_string + ", ";
                aggregated = aggregated + data_string;
            } else {
                data_string = std::to_string(bytes_to_int(
                    multiple_write_query->data[data_index],
                    multiple_write_query->data[data_index + 1]));
                response = response + data_string + ", ";
                aggregated = aggregated + data_string;
            }

            aggregated = aggregated + DISPLAY_FRAME_SEPARATOR + "notes: "
                + addr_data->notes + DISPLAY_FRAME_SEPARATOR;

            add_aggregated_data(addr_data->db_id, transaction_id, slave_id,
                address, 1, data_string);

            data_index += 2;
        }

        add_display_frame(type, query, response, aggregated);

        break;
    case REPORT_SLAVE_ID:
        type = "REPORT SLAVE ID";

        report_slave_id_request = (struct modbus_generic*)
            aggregated_frame->query;
        report_slave_id_response = (struct modbus_report_slave_id_response*)
            aggregated_frame->response;

        query = get_modbus_generic_string(report_slave_id_request,
                                              DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_report_slave_id_response_string(
            report_slave_id_response, DISPLAY_FRAME_SEPARATOR);

        add_display_frame(type, query, response);

        break;
    case READ_FILE_RECORD:
        break;
    case WRITE_FILE_RECORD:
        break;
    case MASK_WRITE_REGISTER:
        type = "MASK WRITE REGISTER";

        mask_write_query = (struct modbus_mask_write*) aggregated_frame->query;
        mask_write_response = (struct modbus_mask_write*)
            aggregated_frame->response;

        query = get_modbus_mask_write_string(mask_write_query,
                                             DISPLAY_FRAME_SEPARATOR);
        response = get_modbus_mask_write_string(mask_write_response,
                                                DISPLAY_FRAME_SEPARATOR);

        add_display_frame(type, query, response);

        break;
    default:
        std::cout << "Function code decoding not yet implemented" << std::endl;
    }

    return true;
}

bool db_manager::add_aggregated_exception_frame(const struct modbus_aggregate
                                                *aggregated_frame)
{
    struct modbus_read_query *read_query;
    struct modbus_single_write *single_write_query;
    struct modbus_generic *exception_status_request;
    struct modbus_diagnostics *diagnostics_query;
    struct modbus_generic *event_counter_request;
    struct modbus_generic *event_log_request;
    struct modbus_multiple_write_query *multiple_write_query;
    struct modbus_generic *report_slave_id_request;
    struct modbus_exception *exception;
    std::string type;
    std::string query;
    std::string response;
    uint8_t function_code;

    function_code = aggregated_frame->function_code - 0x80;

    switch (function_code) {
    case READ_COIL_STATUS:
        type = "READ COIL STATUS EXCEPTION";

        read_query = (struct modbus_read_query*) aggregated_frame->query;

        query = get_modbus_read_query_string(read_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case READ_INPUT_STATUS:
        type = "READ INPUT STATUS EXCEPTION";

        read_query = (struct modbus_read_query*) aggregated_frame->query;

        query = get_modbus_read_query_string(read_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case READ_HOLDING_REGISTERS:
        type = "READ HOLDING REGISTERS EXCEPTION";

        read_query = (struct modbus_read_query*) aggregated_frame->query;

        query = get_modbus_read_query_string(read_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case READ_INPUT_REGISTERS:
        type = "READ INPUT REGISTERS EXCEPTION";

        read_query = (struct modbus_read_query*) aggregated_frame->query;

        query = get_modbus_read_query_string(read_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case FORCE_SINGLE_COIL:
        type = "FORCE SINGLE COIL EXCEPTION";

        single_write_query = (struct modbus_single_write*)
            aggregated_frame->query;

        query = get_modbus_single_write_string(single_write_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case PRESET_SINGLE_REGISTER:
        type = "PRESET SINGLE REGISTER EXCEPTION";

        single_write_query = (struct modbus_single_write*)
            aggregated_frame->query;

        query = get_modbus_single_write_string(single_write_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case READ_EXCEPTION_STATUS:
        type = "READ EXCEPTION STATUS EXCEPTION";

        exception_status_request = (struct modbus_generic*)
            aggregated_frame->query;

        query = get_modbus_generic_string(exception_status_request,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case DIAGNOSTICS:
        type = "DIAGNOSTICS EXCEPTION";

        diagnostics_query = (struct modbus_diagnostics*)
            aggregated_frame->query;

        query = get_modbus_diagnostics_string(diagnostics_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case FETCH_COMM_EVENT_COUNTER:
        type = "FETCH COMM EVENT COUNTER EXCEPTION";

        event_counter_request = (struct modbus_generic*)
            aggregated_frame->query;

        query = get_modbus_generic_string(event_counter_request,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case FETCH_COMM_EVENT_LOG:
        type = "FETCH COMM EVENT LOG EXCEPTION";

        event_log_request = (struct modbus_generic*)
            aggregated_frame->query;

        query = get_modbus_generic_string(event_log_request,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case FORCE_MULTIPLE_COILS:
        type = "FORCE MULTIPLE COILS EXCEPTION";

        multiple_write_query = (struct modbus_multiple_write_query*)
            aggregated_frame->query;

        query = get_modbus_multiple_write_query_string(multiple_write_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case PRESET_MULTIPLE_REGISTERS:
        type = "PRESET MULTIPLE REGISTERS EXCEPTION";

        multiple_write_query = (struct modbus_multiple_write_query*)
            aggregated_frame->query;

        query = get_modbus_multiple_write_query_string(multiple_write_query,
            DISPLAY_FRAME_SEPARATOR);

        break;
    case REPORT_SLAVE_ID:
        type = "REPORT SLAVE ID EXCEPTION";

        report_slave_id_request = (struct modbus_generic*)
            aggregated_frame->query;
        query = get_modbus_generic_string(report_slave_id_request,
            DISPLAY_FRAME_SEPARATOR);

        break;
    default:
        std::cout << "Function code decoding not yet implemented" << std::endl;
    }

    exception = (struct modbus_exception*) aggregated_frame->response;

    response = get_modbus_exception_string(exception, DISPLAY_FRAME_SEPARATOR);

    add_display_frame(type, query, response);

    return true;
}
