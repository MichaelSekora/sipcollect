#ifndef MYSQL_HANDLER_H_INCLUDED
#define MYSQL_HANDLER_H_INCLUDED
MYSQL_RES* mysql_perform_query(MYSQL *connection, char *sql_query);
int connectdb();

#endif
