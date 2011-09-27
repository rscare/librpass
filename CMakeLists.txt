cmake_minimum_required (VERSION 2.8.5)
project (librpass)

include("${CMAKE_SOURCE_DIR}/../cmake/rpass.cmake")

SET (RPASS_LIBRARY_FILES librpass.c rpass.h)
SET (RPASS_LIBRARY_GTK_FILES getpassphrasegtk.h getpassphrasegtk.c)
SET (RPASS_LIBRARY_NCURSES_FILES getpassphrasencurses.h getpassphrasencurses.c)
SET (RPASS_PASSWORD_FILES password_functions.c password_functions.h)

add_library (rpass SHARED ${RPASS_LIBRARY_FILES} ${RPASS_LIBRARY_GTK_FILES} ${RPASS_LIBRARY_NCURSES_FILES} ${RPASS_PASSWORD_FILES})

include_directories("${PROJECT_BINARY_DIR}")

option(RPASS_SUPPORT "Compile in support for password storage/retrieval." ON)

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

install (TARGETS rpass LIBRARY DESTINATION lib)
install (FILES rpass.h ${PROJECT_BINARY_DIR}/rpass_sys_config.h password_functions.h DESTINATION include)
