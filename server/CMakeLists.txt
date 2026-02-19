add_executable(cipheator-server
  src/main.cpp
  src/audit.cpp
  src/monitor.cpp
  src/admin_server.cpp
)

target_link_libraries(cipheator-server PRIVATE cipheator_common Threads::Threads)
target_include_directories(cipheator-server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(WIN32)
  target_link_libraries(cipheator-server PRIVATE ws2_32)
endif()
