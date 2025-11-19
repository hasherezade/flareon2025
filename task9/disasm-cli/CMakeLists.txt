cmake_minimum_required (VERSION 3.12)

project (disasm-cli)
find_package(Qt5Core REQUIRED)

include_directories ( ${PARSER_INC} )
include_directories ( ${MINIDIS_DIR}/include )

add_compile_definitions(WITH_QT5)
find_package(Qt5Core REQUIRED)
get_target_property(QtCore_location Qt5::Core LOCATION)

set ( srcs
    main.cpp
)

set ( hdrs
)

add_executable (${PROJECT_NAME} ${srcs} ${hdrs} )

target_link_libraries( ${PROJECT_NAME} Qt5::Core)
target_link_libraries (${PROJECT_NAME} ${MINIDIS_LIB} ${PARSER_LIB} ${CAPSTONE_LIB})

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
