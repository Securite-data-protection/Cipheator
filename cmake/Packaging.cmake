include(GNUInstallDirs)

if (BUILD_CLIENT)
  set(CIPHEATOR_CONFIG_INSTALL_DIR "config")
  configure_file(
    "${CMAKE_SOURCE_DIR}/config/client.conf.in"
    "${CMAKE_BINARY_DIR}/client.conf"
    @ONLY
  )
  install(FILES "${CMAKE_BINARY_DIR}/client.conf" DESTINATION "${CIPHEATOR_CONFIG_INSTALL_DIR}")
  if (EXISTS "${CMAKE_SOURCE_DIR}/server.crt")
    install(FILES "${CMAKE_SOURCE_DIR}/server.crt" DESTINATION "${CIPHEATOR_CONFIG_INSTALL_DIR}")
  else()
    message(WARNING "server.crt not found; installer will not bundle a default CA file")
  endif()
endif()

if (WIN32 AND BUILD_CLIENT AND BUILD_GUI)
  find_program(WINDEPLOYQT_EXECUTABLE NAMES windeployqt windeployqt6)
  if (WINDEPLOYQT_EXECUTABLE)
    install(CODE "set(WINDEPLOYQT_EXECUTABLE \"${WINDEPLOYQT_EXECUTABLE}\")")
    install(CODE "set(CIPHEATOR_INSTALL_PREFIX \"${CMAKE_INSTALL_PREFIX}\")")
    install(CODE "set(CIPHEATOR_INSTALL_EXE \"${CMAKE_INSTALL_PREFIX}/cipheator-client.exe\")")
    install(SCRIPT "${CMAKE_SOURCE_DIR}/cmake/DeployQt.cmake")
  else()
    message(WARNING "windeployqt not found; Windows installer may miss Qt runtime files")
  endif()

  install(CODE "set(CIPHEATOR_INSTALL_PREFIX \"${CMAKE_INSTALL_PREFIX}\")")
  install(CODE "set(CIPHEATOR_INSTALL_EXE \"${CMAKE_INSTALL_PREFIX}/cipheator-client.exe\")")
  install(SCRIPT "${CMAKE_SOURCE_DIR}/cmake/InstallRuntimeDeps.cmake")
endif()

set(CPACK_PACKAGE_NAME "PAK AS Client")
set(CPACK_PACKAGE_VENDOR "Securite Data Protection")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cipheator GUI client")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "PAK_AS")

if (WIN32)
  set(CPACK_GENERATOR "NSIS")
  set(CPACK_NSIS_DISPLAY_NAME "ПАК АС (Клиент)")
  set(CPACK_NSIS_PACKAGE_NAME "ПАК АС (Клиент)")
  set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
endif()

include(CPack)
