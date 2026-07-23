cmake_minimum_required(VERSION 3.27)

project(SMGlobalFinder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED ENV{IDASDK} OR "$ENV{IDASDK}" STREQUAL "")
  message(FATAL_ERROR "Set IDASDK to the IDA SDK root before configuring.")
endif()

include("$ENV{IDASDK}/src/cmake/bootstrap.cmake")
find_package(idasdk REQUIRED)

ida_add_plugin(sm_global_finder
  SOURCES
    src/rtti_scan.cpp
    src/ctree_analysis.cpp
    src/plugin_main.cpp
  METADATA_JSON
    ida-plugin.json
)

if(WIN32)
  set(IDA_INSTALL_DIR "" CACHE PATH "IDA installation directory for plugin deployment")
  set(SM_GLOBAL_FINDER_INSTALL_DIR "${IDA_INSTALL_DIR}")
  if("${SM_GLOBAL_FINDER_INSTALL_DIR}" STREQUAL "")
    file(GLOB SM_GLOBAL_FINDER_INSTALL_CANDIDATES
      LIST_DIRECTORIES true
      "C:/Program Files/IDA Professional *"
      "C:/Program Files/IDA Pro *"
      "C:/Program Files/IDA *")
    list(SORT SM_GLOBAL_FINDER_INSTALL_CANDIDATES
      COMPARE NATURAL
      ORDER DESCENDING)
    list(LENGTH SM_GLOBAL_FINDER_INSTALL_CANDIDATES SM_GLOBAL_FINDER_INSTALL_CANDIDATE_COUNT)
    if(SM_GLOBAL_FINDER_INSTALL_CANDIDATE_COUNT GREATER 0)
      list(GET SM_GLOBAL_FINDER_INSTALL_CANDIDATES 0 SM_GLOBAL_FINDER_INSTALL_DIR)
    endif()
  endif()

  if(NOT "${SM_GLOBAL_FINDER_INSTALL_DIR}" STREQUAL "")
    set(SM_GLOBAL_FINDER_PLUGIN_DIR
      "${SM_GLOBAL_FINDER_INSTALL_DIR}/plugins/sm_global_finder")

    add_custom_command(TARGET sm_global_finder POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E make_directory
        "${SM_GLOBAL_FINDER_PLUGIN_DIR}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:sm_global_finder>"
        "${SM_GLOBAL_FINDER_PLUGIN_DIR}/$<TARGET_FILE_NAME:sm_global_finder>"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/ida-plugin.json"
        "${SM_GLOBAL_FINDER_PLUGIN_DIR}/ida-plugin.json"
      COMMENT "Installing SM Global Finder in ${SM_GLOBAL_FINDER_PLUGIN_DIR}"
    )
  else()
    message(WARNING "No IDA installation found; skipping post-build plugin deployment.")
  endif()
endif()
