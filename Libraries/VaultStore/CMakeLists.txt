add_library(lkb_vault STATIC VaultStore.cpp)
target_link_libraries(lkb_vault PUBLIC lkb_core lkb_crypto SQLite::SQLite3)
target_include_directories(lkb_vault PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestVaultStore tests/TestVaultStore.cpp)
target_link_libraries(TestVaultStore PRIVATE lkb_vault)
add_test(NAME TestVaultStore COMMAND TestVaultStore)
