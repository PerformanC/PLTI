cmake_minimum_required(VERSION 3.22)
project(plti LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(plti SHARED
  src/elf_util.c
  src/plti.c
)

target_include_directories(plti PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(plti PRIVATE PLTI_LOGGING)
endif()

target_link_libraries(plti PRIVATE
  log
  dl
)

target_compile_options(plti PRIVATE
  -Wpedantic
  -Wall
  -Wextra
  -Werror
  -Wformat
  -Wuninitialized
  -Wshadow
  -Wno-variadic-macros
)
