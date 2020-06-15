#include <iostream>
#include <string.h>
#include <mysql.h>

#include "db.h"

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

    return true;
}
