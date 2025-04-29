#/bin/sh
apt install cmake
apt install pkg-config
apt install libmysqlcppconn-dev
apt install libmysql++-dev
apt install libpcap-dev

cmake .
make

