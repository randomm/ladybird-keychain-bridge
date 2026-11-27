add_library(lkb_keychain STATIC MasterKey.cpp SystemVaultSource.cpp)
target_link_libraries(lkb_keychain PUBLIC lkb_core)
target_include_directories(lkb_keychain PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestMasterKey tests/TestMasterKey.cpp)
target_link_libraries(TestMasterKey PRIVATE lkb_keychain)
add_test(NAME TestMasterKey COMMAND TestMasterKey)

add_executable(TestSystemVaultProbes tests/TestSystemVaultProbes.cpp)
target_link_libraries(TestSystemVaultProbes PRIVATE lkb_keychain)
add_test(NAME TestSystemVaultProbes COMMAND TestSystemVaultProbes)

if(APPLE)
    add_library(lkb_secitem STATIC SecItemKeychainBackend.mm SystemVaultSourceProbe.mm)
    target_link_libraries(lkb_secitem PUBLIC lkb_keychain "-framework Security" "-framework CoreFoundation" "-framework Foundation")

    add_executable(TestSecItemCompile tests/TestSecItemCompile.cpp)
    target_link_libraries(TestSecItemCompile PRIVATE lkb_secitem)
    add_test(NAME TestSecItemCompile COMMAND TestSecItemCompile)

    add_executable(lkb-smoke tools/smoke_main.mm)
    target_link_libraries(lkb-smoke PRIVATE lkb_secitem)

    add_executable(lkb-probe ${CMAKE_SOURCE_DIR}/Meta/Tools/lkb-probe.cpp)
    target_link_libraries(lkb-probe PRIVATE lkb_secitem)
endif()
