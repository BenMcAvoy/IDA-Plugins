cmake_minimum_required(VERSION 3.27)

project(IDA-VTable-Utility LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED ENV{IDASDK} OR "$ENV{IDASDK}" STREQUAL "")
  message(FATAL_ERROR "Set IDASDK to the IDA SDK root before configuring.")
endif()

include("$ENV{IDASDK}/src/cmake/bootstrap.cmake")
find_package(idasdk REQUIRED)

ida_add_plugin(pseudocode_xrefs
  SOURCES
    src/pseudocode_xrefs.cpp
  METADATA_JSON
    ida-plugin.json
)

if(WIN32)
  set(IDA_INSTALL_DIR "" CACHE PATH "IDA installation directory for plugin deployment")
  set(IDA_VTABLE_UTILITY_INSTALL_DIR "${IDA_INSTALL_DIR}")
  if("${IDA_VTABLE_UTILITY_INSTALL_DIR}" STREQUAL "")
    file(GLOB IDA_VTABLE_UTILITY_INSTALL_CANDIDATES
      LIST_DIRECTORIES true
      "C:/Program Files/IDA Professional *"
      "C:/Program Files/IDA Pro *"
      "C:/Program Files/IDA *")
    list(SORT IDA_VTABLE_UTILITY_INSTALL_CANDIDATES
      COMPARE NATURAL
      ORDER DESCENDING)
    list(LENGTH IDA_VTABLE_UTILITY_INSTALL_CANDIDATES IDA_VTABLE_UTILITY_INSTALL_CANDIDATE_COUNT)
    if(IDA_VTABLE_UTILITY_INSTALL_CANDIDATE_COUNT GREATER 0)
      list(GET IDA_VTABLE_UTILITY_INSTALL_CANDIDATES 0 IDA_VTABLE_UTILITY_INSTALL_DIR)
    endif()
  endif()

  if(NOT "${IDA_VTABLE_UTILITY_INSTALL_DIR}" STREQUAL "")
    set(IDA_VTABLE_UTILITY_PLUGIN_DIR
      "${IDA_VTABLE_UTILITY_INSTALL_DIR}/plugins/pseudocode_xrefs")

    add_custom_command(TARGET pseudocode_xrefs POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E make_directory
        "${IDA_VTABLE_UTILITY_PLUGIN_DIR}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:pseudocode_xrefs>"
        "${IDA_VTABLE_UTILITY_PLUGIN_DIR}/$<TARGET_FILE_NAME:pseudocode_xrefs>"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/ida-plugin.json"
        "${IDA_VTABLE_UTILITY_PLUGIN_DIR}/ida-plugin.json"
      COMMENT "Installing IDA-VTable-Utility in ${IDA_VTABLE_UTILITY_PLUGIN_DIR}"
    )
  else()
    message(WARNING "No IDA installation found; skipping post-build plugin deployment.")
  endif()
endif()
