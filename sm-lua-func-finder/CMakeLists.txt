cmake_minimum_required(VERSION 3.27)

project(SMLuaFuncFinder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED ENV{IDASDK} OR "$ENV{IDASDK}" STREQUAL "")
  message(FATAL_ERROR "Set IDASDK to the IDA SDK root before configuring.")
endif()

include("$ENV{IDASDK}/src/cmake/bootstrap.cmake")
find_package(idasdk REQUIRED)

ida_add_plugin(sm_lua_func_finder
  SOURCES
    src/lua_reg_array.cpp
    src/reg_scan.cpp
    src/naming.cpp
    src/lua_api_docs_lookup.cpp
    src/lua_api_docs.gen.cpp
    src/lua_argcount_collapse.cpp
    src/plugin_main.cpp
  METADATA_JSON
    ida-plugin.json
)

if(WIN32)
  set(IDA_INSTALL_DIR "" CACHE PATH "IDA installation directory for plugin deployment")
  set(SM_LUA_FUNC_FINDER_INSTALL_DIR "${IDA_INSTALL_DIR}")
  if("${SM_LUA_FUNC_FINDER_INSTALL_DIR}" STREQUAL "")
    file(GLOB SM_LUA_FUNC_FINDER_INSTALL_CANDIDATES
      LIST_DIRECTORIES true
      "C:/Program Files/IDA Professional *"
      "C:/Program Files/IDA Pro *"
      "C:/Program Files/IDA *")
    list(SORT SM_LUA_FUNC_FINDER_INSTALL_CANDIDATES
      COMPARE NATURAL
      ORDER DESCENDING)
    list(LENGTH SM_LUA_FUNC_FINDER_INSTALL_CANDIDATES SM_LUA_FUNC_FINDER_INSTALL_CANDIDATE_COUNT)
    if(SM_LUA_FUNC_FINDER_INSTALL_CANDIDATE_COUNT GREATER 0)
      list(GET SM_LUA_FUNC_FINDER_INSTALL_CANDIDATES 0 SM_LUA_FUNC_FINDER_INSTALL_DIR)
    endif()
  endif()

  if(NOT "${SM_LUA_FUNC_FINDER_INSTALL_DIR}" STREQUAL "")
    set(SM_LUA_FUNC_FINDER_PLUGIN_DIR
      "${SM_LUA_FUNC_FINDER_INSTALL_DIR}/plugins/sm_lua_func_finder")

    add_custom_command(TARGET sm_lua_func_finder POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E make_directory
        "${SM_LUA_FUNC_FINDER_PLUGIN_DIR}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:sm_lua_func_finder>"
        "${SM_LUA_FUNC_FINDER_PLUGIN_DIR}/$<TARGET_FILE_NAME:sm_lua_func_finder>"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/ida-plugin.json"
        "${SM_LUA_FUNC_FINDER_PLUGIN_DIR}/ida-plugin.json"
      COMMENT "Installing SM Lua Function Finder in ${SM_LUA_FUNC_FINDER_PLUGIN_DIR}"
    )
  else()
    message(WARNING "No IDA installation found; skipping post-build plugin deployment.")
  endif()
endif()
