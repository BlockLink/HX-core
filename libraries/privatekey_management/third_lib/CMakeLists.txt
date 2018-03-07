# build library libbitcoin
message(STATUS "build library libbitcoin")
set( CMAKE_AUTOMOC OFF )


file(GLOB_RECURSE libbitcoin_header_files ${CMAKE_CURRENT_SOURCE_DIR}/libbitcoin/include/*.hpp  ${CMAKE_CURRENT_SOURCE_DIR}/libbitcoin/include/*.h)
file(GLOB_RECURSE libbitcoin_source_files ${CMAKE_CURRENT_SOURCE_DIR}/libbitcoin/src/*.c   ${CMAKE_CURRENT_SOURCE_DIR}/libbitcoin/src/*.cpp)

#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${BOOST_ROOT}/ ${CMAKE_CURRENT_SOURCE_DIR}/third_lib/secp256k1/include)
add_library(privatekey_management_libbitcoin STATIC
            ${libbitcoin_header_files}
			${libbitcoin_source_files})

target_compile_definitions(privatekey_management_libbitcoin PUBLIC
							SECP256K1_STATIC
							BC_STATIC
							WITH_ICU
							WIN32_LEAN_AND_MEAN
							NOMINMAX
							_WIN32_WINNT=0x0600
							_LIB
							NDEBUG
							UNICODE
							_UNICODE
							WIN32
							_WIN32
							WIN64
							_WIN64
							)
target_include_directories(privatekey_management_libbitcoin PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libbitcoin/include  ${BOOST_ROOT}/ )
target_link_libraries(privatekey_management_libbitcoin PUBLIC fc)


install(TARGETS
        privatekey_management_libbitcoin
		RUNTIME DESTINATION bin
	    LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib)



