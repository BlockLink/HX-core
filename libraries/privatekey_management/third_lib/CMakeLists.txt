# build library libbitcoin

message(STATUS "build library libbitcoin_secp256k1")
set( CMAKE_AUTOMOC OFF )

# configure libbitcoin_secp256k1

 
set( LIBBITCOIN_SECP256K1_DIR "${CMAKE_CURRENT_SOURCE_DIR}/secp256k1" )

file( GLOB LIBBITCOIN_SECP256K1_SOURCES "${LIBBITCOIN_SECP256K1_DIR}/src/secp256k1.c" )
add_library( libbitcoin_secp256k1 ${LIBBITCOIN_SECP256K1_SOURCES} )

target_include_directories( libbitcoin_secp256k1 PRIVATE "${LIBBITCOIN_SECP256K1_DIR}" PUBLIC "${LIBBITCOIN_SECP256K1_DIR}/include" )
target_compile_definitions( libbitcoin_secp256k1 PUBLIC
							ENABLE_MODULE_RECOVERY
							ENABLE_MODULE_ECDH
							USE_SCALAR_8X32
							USE_FIELD_10X26
							USE_ENDOMORPHISM
							USE_NUM_NONE
							USE_FIELD_INV_BUILTIN
							USE_SCALAR_INV_BUILTIN
							UNICODE
							_UNICODE
							WIN32
							_WIN32
							WIN64
							_WIN64   
						 )


# End configure libbitcoin_secp256k1

message(STATUS "build library libbitcoin")

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
target_include_directories(privatekey_management_libbitcoin PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/libbitcoin/include  ${BOOST_ROOT}/ ${LIBBITCOIN_SECP256K1_DIR}/include)
target_link_libraries(privatekey_management_libbitcoin PUBLIC libbitcoin_secp256k1 ${Boost_LIBRARIES})


install(TARGETS
        privatekey_management_libbitcoin
		RUNTIME DESTINATION bin
	    LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib)



