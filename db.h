#ifndef DB_H
#define DB_H

#include <string>

typedef struct st_mysql MYSQL;

struct db_manager {
    MYSQL *connection;

    static void display_client_version();
    
    bool open();
    void close();
    bool create_database(std::string db_name);
    bool create_tables();
    bool drop_tables();
};

#endif
