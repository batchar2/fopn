find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem process)

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
    Boost::filesystem
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp
    spdlog::spdlog
    fmt::fmt
    fptn-protocol-lib_static
    ${TUNTAP_LIB})

# --- Channel test ---
add_executable(ChannelTest data/ChannelTest.cpp)
target_link_libraries(ChannelTest PRIVATE ${LIBS})
add_test(NAME ChannelTest COMMAND ChannelTest)

# --- IPv4 Generator test ---
add_executable(IPv4GeneratorTest network/IPv4GeneratorTest.cpp)
target_link_libraries(IPv4GeneratorTest PRIVATE ${LIBS})
add_test(NAME IPv4GeneratorTest COMMAND IPv4GeneratorTest)

# --- IPv6 Generator test ---
add_executable(IPv6GeneratorTest network/IPv6GeneratorTest.cpp)
target_link_libraries(IPv6GeneratorTest PRIVATE ${LIBS})
add_test(NAME IPv6GeneratorTest COMMAND IPv6GeneratorTest)

# --- IPv6 Utils test ---
add_executable(IPv6UtilsTest network/IPv6UtilsTest.cpp)
target_link_libraries(IPv6UtilsTest PRIVATE ${LIBS})
add_test(NAME IPv6UtilsTest COMMAND IPv6UtilsTest)

# --- IPPacket test ---
add_executable(IPPacketTest network/IPPacketTest.cpp)
target_link_libraries(IPPacketTest PRIVATE ${LIBS})
add_test(NAME IPPacketTest COMMAND IPPacketTest)

# --- TUN Device test ---
add_executable(TunDeviceTest network/TunDeviceTest.cpp)
target_link_libraries(TunDeviceTest PRIVATE ${LIBS} Boost::process)
add_test(NAME TunDeviceTest COMMAND TunDeviceTest)

# --- JWT token manager test ---
add_executable(TokenManagerTest jwt_token/TokenManagerTest.cpp)
target_link_libraries(TokenManagerTest PRIVATE ${LIBS})
add_test(NAME TokenManagerTest COMMAND TokenManagerTest)

# --- TLS handshake parsing test ---
add_executable(TlsHandshakeParsingTest network/TlsHandshakeParsingTest.cpp)
target_link_libraries(TlsHandshakeParsingTest PRIVATE ${LIBS} Boost::process)
add_test(NAME TlsHandshakeParsingTest COMMAND TlsHandshakeParsingTest)

# --- ServerHello restamp test ---
add_executable(TlsServerHelloRestampTest network/TlsServerHelloRestampTest.cpp)
target_link_libraries(TlsServerHelloRestampTest PRIVATE ${LIBS})
add_test(NAME TlsServerHelloRestampTest COMMAND TlsServerHelloRestampTest)

# --- Client Stop race condition test ---
add_executable(ClientStopRaceTest network/ClientStopRaceTest.cpp)
target_link_libraries(ClientStopRaceTest PRIVATE GTest::gtest GTest::gtest_main)
add_test(NAME ClientStopRaceTest COMMAND ClientStopRaceTest)

# --- Common user manager test ---
add_executable(CommonUserManagerTest user/CommonUserManagerTest.cpp)
target_link_libraries(CommonUserManagerTest PRIVATE ${LIBS})
add_test(NAME CommonUserManagerTest COMMAND CommonUserManagerTest)
