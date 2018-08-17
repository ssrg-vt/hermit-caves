cmake_minimum_required(VERSION 3.7)
project(hermit_tools)

include(CheckIncludeFiles)
include(../cmake/HermitCore-Paths.cmake)

option(ENABLE_RDMA_MIGRATION "Migration support via RDMA" OFF)

if(NOT DEFINED MAX_ARGC_ENVC)
	set(MAX_ARGC_ENVC 128 CACHE STRING "Maximum size of argc/envc forwarded to
	the	guest (in items)")
endif()

add_compile_options(-std=c99)

if("${TARGET_ARCH}" STREQUAL "aarch64-hermit")
	SET(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
endif()

list(APPEND LIBS "-pthread")
set(SRC proxy.c
	utils.c
	uhyve.c
	uhyve-net.c
	uhyve-migration.c
	uhyve-het-migration.c
	uhyve-x86_64.c
	uhyve-aarch64.c
	uhyve-gdb-x86_64.c
	uhyve-gdb-aarch64.c
	uhyve-remote-mem.c
)

### Optional migration via RDMA
if(ENABLE_RDMA_MIGRATION)
	add_definitions(-D__RDMA_MIGRATION__)
	list(APPEND LIBS "-libverbs")
	set(SRC ${SRC} uhyve-migration-rdma.c)
else()
	remove_definitions(-D__RDMA_MIGRATION__)
endif()

check_include_files(asm/msr-index.h HAVE_MSR_INDEX_H)

if(HAVE_MSR_INDEX_H)
add_definitions(-DHAVE_MSR_INDEX_H=1)
endif()

add_executable(proxy ${SRC})

target_compile_options(proxy PUBLIC ${LIBS})
target_compile_options(proxy PUBLIC -DMAX_ARGC_ENVC=${MAX_ARGC_ENVC})
target_link_libraries(proxy ${LIBS})
target_link_libraries(proxy -lrt)


if("${TARGET_ARCH}" STREQUAL "aarch64-hermit")
	install(TARGETS proxy
		DESTINATION aarch64-hermit/bin)
else()
	install(TARGETS proxy
		DESTINATION x86_64-host/bin)
endif()


# Show include files in IDE
file(GLOB_RECURSE TOOLS_INCLUDES "*.h")
add_custom_target(tools_includes_ide SOURCES ${TOOLS_INCLUDES})
