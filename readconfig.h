#ifndef READCONFIG_H_INCLUDED
#define READCONFIG_H_INCLUDED
#include <string>

class ReadConfig
{
public:
    ReadConfig();
    std::string configfilecontent;
    std::string dbhost;
    std::string dbname;
    std::string dbuser;
    std::string dbpasswd;
    std::string packet_filter;

private:
    int readconfig();
    std::string getconfigparameter(std::string parametername, std::string content);
};
#endif
