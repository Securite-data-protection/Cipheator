cmake_minimum_required(VERSION 3.20)
project(cipheator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_CLIENT "Build client" ON)
option(BUILD_SERVER "Build server" ON)
option(BUILD_GUI "Build Qt GUI client" ON)
option(BUILD_ADMIN "Build admin console" ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_subdirectory(common)

if(BUILD_SERVER)
  add_subdirectory(server)
endif()

if(BUILD_CLIENT)
  add_subdirectory(client)
endif()

if(BUILD_ADMIN)
  add_subdirectory(admin)
endif()
