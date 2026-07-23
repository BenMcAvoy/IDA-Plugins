cmake_minimum_required(VERSION 3.27)

project(IDA-XXHash-Utility LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED ENV{IDASDK} OR "$ENV{IDASDK}" STREQUAL "")
  message(FATAL_ERROR "Set IDASDK to the IDA SDK root before configuring.")
endif()

include("$ENV{IDASDK}/src/cmake/bootstrap.cmake")
find_package(idasdk REQUIRED)

ida_add_plugin(xxhash_collapse
  SOURCES
    src/xxhash_plugin.cpp
    src/xxhash_common.cpp
    src/xxhash_input.cpp
    src/xxhash32_match.cpp
    src/xxhash64_match.cpp
    src/xxhash_synth.cpp
  METADATA_JSON
    ida-plugin.json
)

if(WIN32)
  set(IDA_INSTALL_DIR "" CACHE PATH "IDA installation directory for plugin deployment")
  set(IDA_XXHASH_UTILITY_INSTALL_DIR "${IDA_INSTALL_DIR}")
  if("${IDA_XXHASH_UTILITY_INSTALL_DIR}" STREQUAL "")
    file(GLOB IDA_XXHASH_UTILITY_INSTALL_CANDIDATES
      LIST_DIRECTORIES true
      "C:/Program Files/IDA Professional *"
      "C:/Program Files/IDA Pro *"
      "C:/Program Files/IDA *")
    list(SORT IDA_XXHASH_UTILITY_INSTALL_CANDIDATES
      COMPARE NATURAL
      ORDER DESCENDING)
    list(LENGTH IDA_XXHASH_UTILITY_INSTALL_CANDIDATES IDA_XXHASH_UTILITY_INSTALL_CANDIDATE_COUNT)
    if(IDA_XXHASH_UTILITY_INSTALL_CANDIDATE_COUNT GREATER 0)
      list(GET IDA_XXHASH_UTILITY_INSTALL_CANDIDATES 0 IDA_XXHASH_UTILITY_INSTALL_DIR)
    endif()
  endif()

  if(NOT "${IDA_XXHASH_UTILITY_INSTALL_DIR}" STREQUAL "")
    set(IDA_XXHASH_UTILITY_PLUGIN_DIR
      "${IDA_XXHASH_UTILITY_INSTALL_DIR}/plugins/xxhash_collapse")

    add_custom_command(TARGET xxhash_collapse POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E make_directory
        "${IDA_XXHASH_UTILITY_PLUGIN_DIR}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:xxhash_collapse>"
        "${IDA_XXHASH_UTILITY_PLUGIN_DIR}/$<TARGET_FILE_NAME:xxhash_collapse>"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/ida-plugin.json"
        "${IDA_XXHASH_UTILITY_PLUGIN_DIR}/ida-plugin.json"
      COMMENT "Installing IDA-XXHash-Utility in ${IDA_XXHASH_UTILITY_PLUGIN_DIR}"
    )
  else()
    message(WARNING "No IDA installation found; skipping post-build plugin deployment.")
  endif()
endif()
