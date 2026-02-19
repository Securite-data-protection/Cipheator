set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CLIENT_SOURCES
  src/client_core.cpp
  src/client_core.h
)

if(BUILD_GUI)
  find_package(Qt6 COMPONENTS Widgets REQUIRED)
  add_executable(cipheator-client
    src/main.cpp
    src/main_window.cpp
    src/main_window.h
    src/login_dialog.cpp
    src/login_dialog.h
    src/secure_guards.cpp
    src/secure_guards.h
    ${CLIENT_SOURCES}
  )
  target_include_directories(cipheator-client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(cipheator-client PRIVATE cipheator_common Qt6::Widgets)
  target_compile_definitions(cipheator-client PRIVATE CIPHEATOR_GUI)
else()
  add_executable(cipheator-client
    src/cli_main.cpp
    ${CLIENT_SOURCES}
  )
  target_include_directories(cipheator-client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(cipheator-client PRIVATE cipheator_common)
endif()
