find_package(GTest REQUIRED)
find_package(Threads REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem locale process)

set(FPTN_CLIENT_DIR "${CMAKE_SOURCE_DIR}/src/fptn-client")

set(LIBS
    GTest::gtest
    GTest::gtest_main
    Boost::boost
    ZLIB::ZLIB
    spdlog::spdlog
    fmt::fmt
    fptn-protocol-lib_static)

# --- AdBlocker test ---
add_executable(AdBlockerTest
  adblock/AdBlockerTest.cpp
  "${FPTN_CLIENT_DIR}/plugins/adblock/adblock.cpp")
target_include_directories(AdBlockerTest PRIVATE "${FPTN_CLIENT_DIR}")
target_link_libraries(AdBlockerTest PRIVATE ${LIBS})
add_test(NAME AdBlockerTest COMMAND AdBlockerTest)

# --- SplitTunneling test ---
add_executable(SplitTunnelingTest split/SplitTunnelingTest.cpp)
target_include_directories(SplitTunnelingTest PRIVATE "${FPTN_CLIENT_DIR}")
target_link_libraries(SplitTunnelingTest PRIVATE ${LIBS} Boost::locale)
add_test(NAME SplitTunnelingTest COMMAND SplitTunnelingTest)

# --- SOCKS5 server test ---
add_executable(Socks5ServerTest
  socks/Socks5ServerTest.cpp
  "${FPTN_CLIENT_DIR}/socks/socks5_server.cpp"
  "${FPTN_CLIENT_DIR}/socks/udp_associate.cpp")
target_include_directories(Socks5ServerTest PRIVATE "${FPTN_CLIENT_DIR}")
# PolicyRoute ходит в системные команды, отсюда Boost::process.
target_link_libraries(Socks5ServerTest PRIVATE ${LIBS} Boost::process
                                               Threads::Threads)
add_test(NAME Socks5ServerTest COMMAND Socks5ServerTest)

# --- DomainBlacklist SNI match test ---
find_package(re2 REQUIRED)
add_executable(DomainBlacklistMatchTest blacklist/DomainBlacklistMatchTest.cpp)
target_include_directories(DomainBlacklistMatchTest PRIVATE "${FPTN_CLIENT_DIR}")
target_link_libraries(
  DomainBlacklistMatchTest PRIVATE ${LIBS} Boost::locale re2::re2)
add_test(NAME DomainBlacklistMatchTest COMMAND DomainBlacklistMatchTest)
