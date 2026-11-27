add_executable(TestCsvRoundtrip tests/TestCsvRoundtrip.cpp)
target_link_libraries(TestCsvRoundtrip PRIVATE lkb_csv)
target_include_directories(TestCsvRoundtrip PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(TestCsvRoundtrip PRIVATE FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
add_test(NAME TestCsvRoundtrip COMMAND TestCsvRoundtrip)

add_library(lkb_csv STATIC CsvBridge.cpp)
target_link_libraries(lkb_csv PUBLIC lkb_vault)
target_include_directories(lkb_csv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(FuzzCsvImport tests/FuzzCsvImport.cpp)
target_link_libraries(FuzzCsvImport PRIVATE lkb_csv)
set_target_properties(FuzzCsvImport PROPERTIES EXCLUDE_FROM_ALL TRUE)
