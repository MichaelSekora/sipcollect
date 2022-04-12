cmake_minimum_required(VERSION 3.0.0)
project(sipcollect VERSION 0.1.0)

include(CTest)
enable_testing()

include(FindPkgConfig)
pkg_check_modules(LIBMYSQLCLIENT REQUIRED mysqlclient)
pkg_check_modules(LIBPCAP REQUIRED libpcap)
 
foreach(FLAG ${LIBMYSQLCLIENT_CFLAGS_OTHER})
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
endforeach()
 
link_directories(${LIBMYSQLCLIENT_LIBRARY_DIRS})
 
add_executable(${PROJECT_NAME} mysql_handler.cpp packet_handler.cpp main.cpp readconfig.cpp)

target_include_directories(${PROJECT_NAME} PRIVATE ${LIBMYSQLCLIENT_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBMYSQLCLIENT_LIBRARIES} pcap)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
