set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 COMPONENTS Widgets REQUIRED)

add_executable(cipheator-admin
  src/main.cpp
  src/admin_window.cpp
  src/admin_window.h
  src/admin_client.cpp
  src/admin_client.h
)

target_include_directories(cipheator-admin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(cipheator-admin PRIVATE cipheator_common Qt6::Widgets)
