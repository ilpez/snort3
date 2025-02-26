
set (INCLUDES
    analyzer.h
    analyzer_command.h
    policy.h
    reload_tracker.h
    snort.h
    snort_config.h
    snort_debug.h
    snort_types.h
    swapper.h
    thread.h
    thread_config.h
)

set (LOCAL_INCLUDES
    ${CMAKE_CURRENT_BINARY_DIR}/lua_bootstrap.h
    ${CMAKE_CURRENT_BINARY_DIR}/lua_finalize.h
)

if ( ENABLE_SHELL )
    set ( SHELL_SOURCES ac_shell_cmd.h ac_shell_cmd.cc)
endif ( ENABLE_SHELL )

add_library (main OBJECT
    analyzer.cc
    analyzer_command.cc
    help.cc
    help.h
    modules.cc
    modules.h
    oops_handler.cc
    oops_handler.h
    policy.cc
    reload_tracker.cc
    shell.h
    shell.cc
    snort.cc
    snort.h
    snort_config.cc
    snort_debug.cc
    snort_module.h
    snort_module.cc
    swapper.cc
    thread.cc
    thread_config.h
    thread_config.cc
    ${INCLUDES}
    ${LOCAL_INCLUDES}
    ${SHELL_SOURCES}
)

add_custom_command (
    OUTPUT lua_bootstrap.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../lua_wrap.sh ${CMAKE_CURRENT_SOURCE_DIR} bootstrap > lua_bootstrap.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap.lua
)

add_custom_command (
    OUTPUT lua_finalize.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../lua_wrap.sh ${CMAKE_CURRENT_SOURCE_DIR} finalize > lua_finalize.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/finalize.lua
)

include_directories (${CMAKE_CURRENT_BINARY_DIR})

install (FILES ${INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/main"
)
