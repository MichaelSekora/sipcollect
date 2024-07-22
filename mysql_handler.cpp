#include "mysql.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>

extern bool use_database;
bool mysqlpresent = false;
MYSQL *conn = nullptr;
int version;
extern std::string dbhost;
extern std::string dbname;
extern std::string dbuser;
extern std::string dbpasswd;

MYSQL_RES *mysql_perform_query(MYSQL *connection, char *sql_query)
{
  if (mysql_query(connection, sql_query))
  {
    printf("\n/// START ////////////////////////////////////////////////////");
    printf("\nMySQL query error : %s\ncheck MySQL configuration in sipcollect.config\n  dbhost:%s\n  dbname:%s\n  dbtablename:sip\n  dbuser:%s\n  dbpasswd:********\n",
           mysql_error(connection), dbhost.c_str(), dbname.c_str(), dbuser.c_str());
    printf("\nquery:%s", sql_query);
    printf("\n///////////////////////////////////////////////////////");
    for(int i = 0; i < 2000; i++)
    {
      printf("%02x ", sql_query[i]);
    }
    printf("\n/// END ////////////////////////////////////////////////////");
    
  }
  return mysql_use_result(connection);
}

int connectdb()
{
  conn = nullptr;
  if (!mysqlpresent)
  {
    printf("\ntrying to connect to Database\n");
    conn = mysql_init(NULL);
    mysql_set_character_set(conn, "utf8mb4");
    mysql_real_connect(conn, dbhost.c_str(), dbuser.c_str(), dbpasswd.c_str(), dbname.c_str(), 3306, NULL, 0);

    version = mysql_get_server_version(conn);
    printf("\nMySQL Version = %d\n", version);
    mysqlpresent = true;
  }
  return 0;
}
