add_library(lkb_service STATIC CapabilityToken.cpp CredentialService.cpp)
target_link_libraries(lkb_service PUBLIC lkb_vault)
target_include_directories(lkb_service PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestCapabilityToken tests/TestCapabilityToken.cpp)
target_link_libraries(TestCapabilityToken PRIVATE lkb_service)
add_test(NAME TestCapabilityToken COMMAND TestCapabilityToken)

add_executable(TestServicePolicy tests/TestServicePolicy.cpp)
target_link_libraries(TestServicePolicy PRIVATE lkb_service)
add_test(NAME TestServicePolicy COMMAND TestServicePolicy)

add_executable(TestAutofill tests/TestAutofill.cpp)
target_link_libraries(TestAutofill PRIVATE lkb_service)
add_test(NAME TestAutofill COMMAND TestAutofill)

add_executable(TestJsCredentials tests/TestJsCredentials.cpp)
target_link_libraries(TestJsCredentials PRIVATE lkb_service)
add_test(NAME TestJsCredentials COMMAND TestJsCredentials)
