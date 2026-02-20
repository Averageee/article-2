cmake_minimum_required(VERSION 3.15)
project(AuthSystem CXX)

set(CMAKE_CXX_STANDARD 20)

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
# 假设 liboqs 安装在标准路径，如果找不到需手动指定 include/lib
find_library(OQS_LIB oqs)

set(COMMON_LIBS OpenSSL::Crypto Boost::system ${OQS_LIB} pthread)

add_executable(server server.cpp)
target_link_libraries(server ${COMMON_LIBS})

add_executable(device device.cpp)
target_link_libraries(device ${COMMON_LIBS})

add_executable(client client.cpp)
target_link_libraries(client ${COMMON_LIBS})
