cmake_minimum_required (VERSION 3.0)

project ( t9_verify_chunk )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libdetours headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
)
set (hdrs
	util.h
	verif.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )

target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
add_dependencies(${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
