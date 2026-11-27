add_library(lkb_keychain STATIC MasterKey.cpp)
target_link_libraries(lkb_keychain PUBLIC lkb_core)
target_include_directories(lkb_keychain PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestMasterKey tests/TestMasterKey.cpp)
target_link_libraries(TestMasterKey PRIVATE lkb_keychain)
add_test(NAME TestMasterKey COMMAND TestMasterKey)

if(APPLE)
    add_library(lkb_secitem STATIC SecItemKeychainBackend.mm)
    target_link_libraries(lkb_secitem PUBLIC lkb_keychain "-framework Security" "-framework CoreFoundation")

    add_executable(TestSecItemCompile tests/TestSecItemCompile.cpp)
    target_link_libraries(TestSecItemCompile PRIVATE lkb_secitem)
    add_test(NAME TestSecItemCompile COMMAND TestSecItemCompile)

    add_executable(lkb-smoke tools/smoke_main.mm)
    target_link_libraries(lkb-smoke PRIVATE lkb_secitem)
endif()
