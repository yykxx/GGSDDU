project(libke)

cmake_minimum_required(VERSION 2.8)

option(REGULAR_FILE_AIO "aio for regular file" ON)
option(STRICT_CHECK "strict check" ON)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    message("build on linux")
    add_definitions(-DUSE_EPOLL)
elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    message("build on windows")
    set(CMAKE_MFC_FLAGS 0)
endif ()

if (${REGULAR_FILE_AIO} STREQUAL "ON")
    message("enable aio for regular file")
    add_definitions(-DKE_AIO_ENABLE_REGULAR_FILE)
else ()
    message("disable aio for regular file")
endif ()

if (${STRICT_CHECK} STREQUAL "ON")
    message("enable strict check")
    add_definitions(-DKE_STRICT_CHECK)
else ()
    message("disable strict check")
endif ()

set(SRC 
	ke/aio.c
	ke/aio.h
	ke/bitset.c
	ke/bitset.h
	ke/bstree.c
	ke/bstree.h
	ke/defs.h
	ke/dlist.h
	ke/hash_table.c
	ke/hash_table.h
	ke/list.h
	ke/lookaside_list.c
	ke/lookaside_list.h
	ke/map.c
	ke/map.h
	ke/mempool.c
	ke/mempool.h
	ke/queue.h
	ke/rbtree.c
	ke/rbtree.h
	ke/set.c
	ke/set.h
	ke/splay.c
	ke/splay.h
	ke/stack.h)
	
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

include_directories(${PROJECT_SOURCE_DIR})

add_library(ke ${SRC})
