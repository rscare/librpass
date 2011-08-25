cmake_minimum_required (VERSION 2.8.5)
project (rpass)

SET (RPASS_LIBRARY_FILES librpass.c rpass.h getpassphrasegtk.h getpassphrasegtk.c getpassphrasencurses.h getpassphrasencurses.c)

add_executable(testrpassd testrpassd.c ${RPASS_LIBRARY_FILES})
add_executable(rpassd rpassd.cpp ${RPASS_LIBRARY_FILES})
add_library (rpass ${RPASS_LIBRARY_FILES})

include_directories("${PROJECT_BINARY_DIR}")

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# Find libgcrypt
find_package(Libgcrypt REQUIRED)
include_directories(${LIBGCRYPT_INCLUDE_DIR})
set(RPASS_LIBRARIES ${RPASS_LIBRARIES} ${LIBGCRYPT_LIBRARIES})

# Find libncurses
option(USE_NCURSES "Attempt to use ncurses" ON)
if (USE_NCURSES)
  set (CURSES_NEED_NCURSES TRUE)
  find_package(Curses)
  if (CURSES_FOUND)
    message(STATUS "Using ncurses...")
    include_directories(${CURSES_INCLUDE_DIR})
    set(RPASS_LIBRARIES ${RPASS_LIBRARIES} ${CURSES_LIBRARIES})
   else (CURSES_FOUND)
     message(WARNING "Failed to find ncurses...")
     set(USE_NCURSES OFF)
  endif (CURSES_FOUND)
endif (USE_NCURSES)

# Find gtk2
option(USE_GTK2 "Attempt to use GTK2" ON)

if (USE_GTK2)
  find_package(GTK2 COMPONENTS gtk)

  if (GTK2_FOUND)
    message (STATUS "Using GTK2...")
    include_directories(${GTK2_INCLUDE_DIRS})
    set(RPASS_LIBRARIES ${RPASS_LIBRARIES} ${GTK2_LIBRARIES})
  else (GTK2_FOUND)
    message (WARNING "Failed to find GTK2...")
    set(USE_GTK2 OFF)
  endif (GTK2_FOUND)
endif (USE_GTK2)

configure_file(
  "${PROJECT_SOURCE_DIR}/rpass_sys_config.h.in"
  "${PROJECT_BINARY_DIR}/rpass_sys_config.h"
  )

target_link_libraries(testrpassd ${RPASS_LIBRARIES})
target_link_libraries(rpassd ${RPASS_LIBRARIES})

install (TARGETS rpass DESTINATION lib)
install (FILES rpass.h DESTINATION include)
