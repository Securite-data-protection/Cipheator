add_library(cipheator_common)

set(COMMON_HEADERS
  include/cipheator/base64.h
  include/cipheator/bytes.h
  include/cipheator/config.h
  include/cipheator/protocol.h
  include/cipheator/secure_memory.h
  include/cipheator/crypto.h
  include/cipheator/gost_cli.h
  include/cipheator/auth.h
  include/cipheator/net.h
  include/cipheator/tls.h
  include/cipheator/pki.h
)

set(COMMON_SOURCES
  src/base64.cpp
  src/bytes.cpp
  src/config.cpp
  src/protocol.cpp
  src/secure_memory.cpp
  src/crypto.cpp
  src/gost_cli.cpp
  src/auth.cpp
  src/net.cpp
  src/tls.cpp
  src/pki.cpp
)

target_sources(cipheator_common PRIVATE ${COMMON_HEADERS} ${COMMON_SOURCES})

target_include_directories(cipheator_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_definitions(cipheator_common PRIVATE CIPHEATOR_BUILD)

target_link_libraries(cipheator_common PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
  target_link_libraries(cipheator_common PUBLIC ws2_32)
endif()
