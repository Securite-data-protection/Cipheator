if (NOT WINDEPLOYQT_EXECUTABLE)
  message(WARNING "windeployqt not found; skipping Qt deployment")
  return()
endif()
if (NOT DEFINED CIPHEATOR_INSTALL_EXE)
  message(FATAL_ERROR "CIPHEATOR_INSTALL_EXE not set")
endif()
if (NOT DEFINED CIPHEATOR_INSTALL_PREFIX)
  message(FATAL_ERROR "CIPHEATOR_INSTALL_PREFIX not set")
endif()

execute_process(
  COMMAND "${WINDEPLOYQT_EXECUTABLE}"
          --release
          --no-translations
          --no-opengl-sw
          --no-system-d3d-compiler
          --dir "${CIPHEATOR_INSTALL_PREFIX}"
          "${CIPHEATOR_INSTALL_EXE}"
  RESULT_VARIABLE deploy_result
)

if (NOT deploy_result EQUAL 0)
  message(WARNING "windeployqt failed with code ${deploy_result}")
endif()
