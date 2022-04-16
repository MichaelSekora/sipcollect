#include <iostream>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include "readconfig.h"
using namespace std;

ReadConfig::ReadConfig()
{
    dbhost = "";
    dbuser = "";
    dbpasswd = "";
    packet_filter = "";
    readconfig();
}

string ReadConfig::getconfigparameter(string parametername, string content)
{
    // find line with parameter
    size_t firstpos = string::npos;
    size_t secondpos = string::npos;
    size_t param_pos1 = content.find(parametername, 0);
    if (param_pos1 != string::npos)
    {
        firstpos = content.find("\"", param_pos1 + 2);
        if (firstpos == string::npos)
        {
            cout << "\n"
                 << parametername << " invalid! check `sipcollect.config`\n";
            exit(1);
        }
        secondpos = content.find("\"", firstpos + 1);
        if (secondpos == string::npos)
        {
            cout << "\n"
                 << parametername << " invalid! check `sipcollect.config`\n";
            exit(1);
        }
    }
    else
    {
        cout << "\n"
             << parametername << " missing! check `sipcollect.config`\n";
        exit(1);
    }
    return content.substr(firstpos + 1, secondpos - firstpos - 1);
}

#include <limits.h>
#include <unistd.h>

std::string getexepath()
{
    char result[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    return std::string(result, (count > 0) ? count : 0);
}

int ReadConfig::readconfig()
{
    configfilecontent = "";
    string line;
    string tmpstrname = getexepath();
    string filename = tmpstrname + ".config";
    ifstream myfile(filename);
    if (myfile.is_open())
    {
        while (getline(myfile, line))
        {
            configfilecontent = configfilecontent + line;
        }
        dbhost = getconfigparameter("dbhost", configfilecontent);
        dbname = getconfigparameter("dbname", configfilecontent);
        dbuser = getconfigparameter("dbuser", configfilecontent);
        dbpasswd = getconfigparameter("dbpasswd", configfilecontent);
        packet_filter = getconfigparameter("packet_filter", configfilecontent);

        myfile.close();
    }
    else
    {
        cout << "\n Unable to open config-file `sipcollect.config`\n";
        exit(1);
    }
    return 0;
}
