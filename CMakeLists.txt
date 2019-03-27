# ==============================================================================
# CMakeLists.txt
#
# Copyright (C) 2019  xcp-clipboardd
# Copyright (C) 2019  Vates SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ==============================================================================

cmake_minimum_required(VERSION 3.13.4)

# ------------------------------------------------------------------------------
# Config & flags.
# ------------------------------------------------------------------------------

project(xcp-clipboardd VERSION 1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)

set(XCP_CLIPBOARDD_BIN xcp-clipboardd)

set(CUSTOM_C_FLAGS
  -Wall
  -Wcast-align
  -Wconversion
  -Werror
  -Wextra
  -Wfloat-equal
  -Wformat-nonliteral
  -Wpointer-arith
  -Wsign-conversion
)

if (CMAKE_C_COMPILER_ID MATCHES "GNU")
  list(APPEND CUSTOM_C_FLAGS
    -Wlogical-op
  )
endif ()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
set(LIBS -lxenstore)

# ------------------------------------------------------------------------------
# Sources.
# ------------------------------------------------------------------------------

set(SOURCES xcp-clipboardd.c)

# ------------------------------------------------------------------------------
# Binary.
# ------------------------------------------------------------------------------

add_compile_options(${CUSTOM_C_FLAGS})

add_executable(${XCP_CLIPBOARDD_BIN} ${SOURCES})
set_property(TARGET ${XCP_CLIPBOARDD_BIN} PROPERTY LINKER_LANGUAGE C)

target_link_libraries(${XCP_CLIPBOARDD_BIN} PRIVATE ${LIBS})

include(GNUInstallDirs)

install(TARGETS ${XCP_CLIPBOARDD_BIN}
  RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
