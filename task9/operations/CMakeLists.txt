cmake_minimum_required ( VERSION 3.12 )

project ( task9_reproduce )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	parse_records.cpp
)

set (hdrs
	util.h
	ffuncs.h
	inverse.h
	parse_records.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
