# Find rpass library

find_path(LIBRPASS_INCLUDE_DIR rpass.h)

find_library(LIBRPASS_LIBRARY rpass)

if (LIBRPASS_INCLUDE_DIR AND LIBRPASS_LIBRARY)
  set(LIBRPASS_LIBRARIES ${LIBRPASS_LIBRARY})
  set(LIBRPASS_FOUND "YES")
else (LIBRPASS_INCLUDE_DIR AND LIBRPASS_LIBRARY)
  set(LIBRPASS_FOUND "NO")
endif (LIBRPASS_INCLUDE_DIR AND LIBRPASS_LIBRARY)

if (LIBRPASS_FOUND)
  find_package(Libgcrypt REQUIRED)
  set(LIBRPASS_INCLUDE_DIR ${LIBRPASS_INCLUDE_DIR} ${LIBGCRYPT_INCLUDE_DIR})
  set(LIBRPASS_LIBRARIES ${LIBRPASS_LIBRARIES} ${LIBGCRYPT_LIBRARIES})

  set (CURSES_NEED_CURSES TRUE)
  find_package(Curses REQUIRED)
  set(LIBRPASS_INCLUDE_DIR ${LIBRPASS_INCLUDE_DIR} ${CURSES_INCLUDE_DIR})
  set(LIBRPASS_LIBRARIES ${LIBRPASS_LIBRARIES} ${CURSES_LIBRARIES})

  find_package(GTK2 COMPONENTS gtk)
  set(LIBRPASS_INCLUDE_DIR ${LIBRPASS_INCLUDE_DIR} ${GTK2_INCLUDE_DIRS})
  set(LIBRPASS_LIBRARIES ${LIBRPASS_LIBRARIES} ${GTK2_LIBRARIES})
endif (LIBRPASS_FOUND)
