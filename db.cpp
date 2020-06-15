#include <stdio.h>
#include <mysql.h>

#include "db.h"

void display_version()
{
    printf("The MySQL client version is: %s\n", mysql_get_client_info());
}
