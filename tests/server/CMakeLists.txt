find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(prometheus-cpp REQUIRED)
find_package(httplib REQUIRED)

if(WIN32)
  set(TUNTAP_LIB Wintun rpcrt4)
else()
  set(TUNTAP_LIB tuntap++)
endif()

set(PLATFORM_SPECIFIC_LIBS "")
if(APPLE)
  set(PLATFORM_SPECIFIC_LIBS "-framework Security" "-framework CoreFoundation")
endif()

set(LIBS
    GTest::gtest
    GTest::gtest_main
    Boost::boost
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp
    spdlog::spdlog
    fmt::fmt
    httplib::httplib
    fptn-protocol-lib_static
    prometheus-cpp::prometheus-cpp
    ${TUNTAP_LIB}
    ${PLATFORM_SPECIFIC_LIBS})

set(DOMAIN_LIST_SRC ${FPTN_SERVER_PATH}/filter/domain_list/domain_list.h
                    ${FPTN_SERVER_PATH}/filter/domain_list/domain_list.cpp)

include_directories(${FPTN_SERVER_PATH})

# --- MetricTest test ---
add_executable(MetricTest statistic/MetricTest.cpp ${FPTN_SERVER_PATH}/statistic/metrics.h ${FPTN_SERVER_PATH}/statistic/metrics.cpp)
target_link_libraries(MetricTest PRIVATE ${LIBS})
add_test(NAME MetricTest COMMAND MetricTest)

# --- AntiScan test ---
add_executable(AntiScanTest filter/antiscan/AntiScanTest.cpp ${FPTN_SERVER_PATH}/filter/filters/antiscan/antiscan.h
                            ${FPTN_SERVER_PATH}/filter/filters/antiscan/antiscan.cpp)
target_link_libraries(AntiScanTest PRIVATE ${LIBS})
add_test(NAME AntiScanTest COMMAND AntiScanTest)

# --- AntiSpam test ---
add_executable(AntiSpamTest filter/antispam/AntiSpamTest.cpp ${FPTN_SERVER_PATH}/filter/filters/antispam/antispam.h
                            ${FPTN_SERVER_PATH}/filter/filters/antispam/antispam.cpp)
target_link_libraries(AntiSpamTest PRIVATE ${LIBS})
add_test(NAME AntiSpamTest COMMAND AntiSpamTest)

# --- BitTorrent test ---
add_executable(
  BitTorrentTest filter/bittorrent/BitTorrentTest.cpp ${FPTN_SERVER_PATH}/filter/filters/bittorrent/bittorrent.h
                 ${FPTN_SERVER_PATH}/filter/filters/bittorrent/bittorrent.cpp)
target_link_libraries(BitTorrentTest PRIVATE ${LIBS})
add_test(NAME BitTorrentTest COMMAND BitTorrentTest)

# --- AdBlock test ---
add_executable(
  AdBlockTest filter/adblock/AdBlockTest.cpp ${FPTN_SERVER_PATH}/filter/filters/adblock/adblock.h
              ${FPTN_SERVER_PATH}/filter/filters/adblock/adblock.cpp ${DOMAIN_LIST_SRC})
target_link_libraries(AdBlockTest PRIVATE ${LIBS})
add_test(NAME AdBlockTest COMMAND AdBlockTest)

# --- DomainBlacklist test ---
add_executable(
  DomainBlacklistTest filter/domain_blacklist/DomainBlacklistTest.cpp
                      ${FPTN_SERVER_PATH}/filter/filters/domain_blacklist/domain_blacklist.h
                      ${FPTN_SERVER_PATH}/filter/filters/domain_blacklist/domain_blacklist.cpp
                      ${DOMAIN_LIST_SRC})
target_link_libraries(DomainBlacklistTest PRIVATE ${LIBS})
add_test(NAME DomainBlacklistTest COMMAND DomainBlacklistTest)

# --- Traffic shaper test ---
add_executable(
  LeakyBucketTest traffic_shaper/LeakyBucketTest.cpp
                  ${FPTN_SERVER_PATH}/traffic_shaper/leaky_bucket.h
                  ${FPTN_SERVER_PATH}/traffic_shaper/leaky_bucket.cpp)
target_link_libraries(LeakyBucketTest PRIVATE ${LIBS})
add_test(NAME LeakyBucketTest COMMAND LeakyBucketTest)
