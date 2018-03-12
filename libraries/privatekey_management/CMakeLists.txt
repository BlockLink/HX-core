message(STATUS "Configuring project privatekey_management located in: ${CMAKE_CURRENT_SOURCE_DIR}")


find_package(Boost REQUIRED COMPONENTS thread date_time system filesystem program_options signals serialization chrono unit_test_framework context locale iostreams regex)

if (Boost_FOUND)
	message(STATUS "found boost library!")
else (Boost_FOUND)
	message(STATUS "cannot found Boost library!")
endif()


add_subdirectory(third_lib)

# build library privatekey_management
message(STATUS "build library privatekey_management")
file(GLOB_RECURSE HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp   ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h)
message(STATUS "HEADERS: ${HEADERS}")

set(sources
   private_key.cpp
   database_privatekey.cpp
   ${HEADERS}
   )


set(BOOST_INCLUDE_DIR $ENV{BOOST_ROOT})

add_library( privatekey_management
             ${sources}
             ${HEADERS} )


target_link_libraries( privatekey_management PUBLIC privatekey_management_libbitcoin graphene_chain ${CMAKE_CURRENT_SOURCE_DIR}/third_lib/threadsafestatics.lib)
target_include_directories( privatekey_management
                            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include 
							PRIVATE ${BOOST_INCLUDE_DIR}/)
	




add_executable( privatekey_management_exe_test main.cpp )
target_link_libraries(privatekey_management_exe_test PRIVATE privatekey_management ${Boost_LIBRARIES} ${CMAKE_CURRENT_SOURCE_DIR}/third_lib/threadsafestatics.lib)
target_include_directories(privatekey_management_exe_test PRIVATE ${BOOST_ROOT}/)


if (USE_PCH)
  set_target_properties(privatekey_management PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
  cotire(privatekey_management)
endif(USE_PCH)

install( TARGETS
   privatekey_management

   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)
install( FILES ${HEADERS} DESTINATION "include/graphene/privatekey_management" )