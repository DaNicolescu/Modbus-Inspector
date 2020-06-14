#include <stdio.h>
#include <mysql.h>

int main(int argc, char *argv[]){
  printf("The MySQL client version is: %s\n", mysql_get_client_info());
}
