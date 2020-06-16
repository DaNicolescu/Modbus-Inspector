#include <iostream>
#include <string.h>
#include <mysql.h>

#include "db.h"
#include "device_struct.h"
#include "modbus.h"
#include "utils.h"

void db_manager::display_client_version()
{
    std::cout << "The DB client version is: " << mysql_get_client_info()
        << std::endl;
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

    return true;
}

void db_manager::close()
{
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
                        "`run_indicator_status` TINYINT UNSIGNED,"
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

    query = "CREATE TABLE IF NOT EXISTS `aggregated_frames` ("
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
            "`data` TEXT)";

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

    query = "DROP TABLE `aggregated_frames`";

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

bool db_manager::add_address(struct address_struct *address,
                             uint8_t slave_id)
{
    std::string query = "INSERT INTO `addresses`(slave_id, address, "
                        "description, notes) VALUES("
                        + std::to_string(slave_id) + ", "
                        + std::to_string(address->address) + ", '"
                        + address->description + "', '"
                        + address->notes + "')";

    std::cout << "db query: " << query << std::endl;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    address->db_id = mysql_insert_id(this->connection);

    return true;
}

bool db_manager::add_read_query(struct modbus_read_query *modbus_struct)
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

    std::cout << "db query: " << query << std::endl;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}

bool db_manager::add_read_response(struct modbus_read_response *modbus_struct)
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

    std::cout << "db query: " << query << std::endl;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}

bool db_manager::add_single_write(struct modbus_single_write *modbus_struct,
                                  uint8_t type)
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

    std::cout << "db query: " << query << std::endl;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}

bool db_manager::add_multiple_write_query(struct modbus_multiple_write_query
                                          *modbus_struct)
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

    std::cout << "db query: " << query << std::endl;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}

bool db_manager::add_multiple_write_response(
    struct modbus_multiple_write_response *modbus_struct)
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

    std::cout << "db query: " << query << std::endl;

    if (mysql_query(this->connection, query.c_str())) {
        std::cout << mysql_error(this->connection) << std::endl;
        mysql_close(this->connection);

        return false;
    }

    return true;
}
