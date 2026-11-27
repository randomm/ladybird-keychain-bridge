add_library(lkb_crypto STATIC AesGcm.cpp Hkdf.cpp)
target_link_libraries(lkb_crypto PUBLIC lkb_core OpenSSL::Crypto)
target_include_directories(lkb_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestCrypto tests/TestCrypto.cpp)
target_link_libraries(TestCrypto PRIVATE lkb_crypto)
add_test(NAME TestCrypto COMMAND TestCrypto)
