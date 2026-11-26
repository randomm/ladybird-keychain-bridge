cmake_minimum_required(VERSION 3.25)
project(ladybird-keychain-bridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Local macOS (brew) hints; harmless on Linux/CI where env supplies paths.
list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/openssl@3" "/usr/local/opt/openssl@3" "/opt/homebrew")

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

enable_testing()

foreach(dir Core KeychainCore CredentialCrypto VaultStore CredentialService BridgeProto CsvBridge)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/Libraries/${dir}/CMakeLists.txt)
        add_subdirectory(Libraries/${dir})
    endif()
endforeach()
