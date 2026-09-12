find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem)

if(WIN32)
  set(TUNTAP_LIB Wintun rpcrt4)
  add_definitions(-D_WIN32_WINNT=0x0601)
else()
  set(TUNTAP_LIB tuntap++)
endif()

set(LIBS
    GTest::gtest
    GTest::gtest_main
    Boost::boost
    Boost::random
    Boost::process
    Boost::filesystem
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp
    spdlog::spdlog
    fmt::fmt
    fptn-protocol-lib_static
    ${TUNTAP_LIB})

# --- ApiClient test ---
add_executable(ApiClientTest api_client/ApiClientTest.cpp)
target_link_libraries(ApiClientTest PRIVATE ${LIBS})
add_test(NAME ApiClientTest COMMAND ApiClientTest)

# --- Protocol policy tests ---
add_executable(SerializerPolicyTest protocol/SerializerPolicyTest.cpp)
target_link_libraries(SerializerPolicyTest PRIVATE ${LIBS})
add_test(NAME SerializerPolicyTest COMMAND SerializerPolicyTest)
