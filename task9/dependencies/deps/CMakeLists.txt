cmake_minimum_required ( VERSION 3.12 )

project ( task9_deps )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libdetours headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
)

set (hdrs
	util.h
)

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )

target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )
add_dependencies(${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
