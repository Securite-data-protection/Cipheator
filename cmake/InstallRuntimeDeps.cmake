if (NOT DEFINED CIPHEATOR_INSTALL_EXE)
  message(FATAL_ERROR "CIPHEATOR_INSTALL_EXE not set")
endif()
if (NOT DEFINED CIPHEATOR_INSTALL_PREFIX)
  message(FATAL_ERROR "CIPHEATOR_INSTALL_PREFIX not set")
endif()

file(GET_RUNTIME_DEPENDENCIES
  EXECUTABLES "${CIPHEATOR_INSTALL_EXE}"
  RESOLVED_DEPENDENCIES_VAR resolved_deps
  UNRESOLVED_DEPENDENCIES_VAR unresolved_deps
  POST_EXCLUDE_REGEXES
    ".*[/\\]Windows[/\\]System32[/\\].*"
    ".*[/\\]Windows[/\\]SysWOW64[/\\].*"
    ".*api-ms-win.*"
    ".*ext-ms-.*"
)

if (unresolved_deps)
  message(WARNING "Unresolved runtime deps: ${unresolved_deps}")
endif()

foreach (dep IN LISTS resolved_deps)
  if (EXISTS "${dep}")
    file(INSTALL DESTINATION "${CIPHEATOR_INSTALL_PREFIX}" TYPE SHARED_LIBRARY FILES "${dep}")
  endif()
endforeach()
