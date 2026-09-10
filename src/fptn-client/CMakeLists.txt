project(fptn-client)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(APPLE OR UNIX)
  set(TUNTAP_LIB tuntap++)
else()
  set(TUNTAP_LIB Wintun rpcrt4 iphlpapi Kernel32.lib)
endif()

find_package(OpenSSL REQUIRED)
find_package(argparse REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem process locale)
find_package(ZLIB REQUIRED)
find_package(httplib REQUIRED)
find_package(libidn2 REQUIRED)
find_package(re2 REQUIRED)
find_package(nlohmann_json REQUIRED)
include_directories(${nlohmann_json_INCLUDE_DIRS})

## brotli
find_package(brotli REQUIRED)
find_path(BROTLI_INCLUDE_DIR "brotli/decode.h" REQUIRED)
include_directories(${BROTLI_INCLUDE_DIR})
find_library(BROTLI_DEC_LIB NAMES brotlidec REQUIRED)
find_library(BROTLI_COMMON_LIB NAMES brotlicommon REQUIRED)
find_library(BROTLI_ENC_LIB NAMES brotlienc REQUIRED)

if (FPTN_OPENWRT)
  set(ADBLOCK_SOURCES "")
else()
  set(ADBLOCK_BLOCKLIST_GZ "${CMAKE_CURRENT_BINARY_DIR}/blocklist.gz")
  set(ADBLOCK_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/blocklist_data.generated.cpp")
  add_custom_command(
    OUTPUT "${ADBLOCK_GENERATED}"
    COMMAND ${CMAKE_COMMAND} -DGZ=${ADBLOCK_BLOCKLIST_GZ}
            -DOUTPUT=${ADBLOCK_GENERATED} -DSYMBOL=kBlocklistGz
            -P "${CMAKE_SOURCE_DIR}/depends/cmake/FetchBlocklist.cmake"
    DEPENDS "${CMAKE_SOURCE_DIR}/depends/cmake/FetchBlocklist.cmake"
    COMMENT "Downloading and embedding ad-block domain list"
    VERBATIM)
  set_source_files_properties(
    "${ADBLOCK_GENERATED}" PROPERTIES GENERATED TRUE SKIP_CLANG_TIDY ON)
  set(ADBLOCK_SOURCES plugins/adblock/adblock.h plugins/adblock/adblock.cpp "${ADBLOCK_GENERATED}")
endif()

set(SPLIT_TUNNEL_DOMAINS_LIST "${CMAKE_SOURCE_DIR}/deploy/domain_blacklist/russia.txt")
set(SPLIT_TUNNEL_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/split_tunnel_domains.generated.h")
add_custom_command(
  OUTPUT "${SPLIT_TUNNEL_GENERATED}"
  COMMAND ${CMAKE_COMMAND} -DINPUT=${SPLIT_TUNNEL_DOMAINS_LIST} -DOUTPUT=${SPLIT_TUNNEL_GENERATED}
          -DBASE=${FPTN_CLIENT_DEFAULT_SPLIT_TUNNEL_DOMAINS} -P
          "${CMAKE_SOURCE_DIR}/depends/cmake/GenerateSplitTunnelDomains.cmake"
  DEPENDS "${SPLIT_TUNNEL_DOMAINS_LIST}" "${CMAKE_SOURCE_DIR}/depends/cmake/GenerateSplitTunnelDomains.cmake"
  COMMENT "Embedding default split-tunnel domain list"
  VERBATIM)
set_source_files_properties("${SPLIT_TUNNEL_GENERATED}" PROPERTIES GENERATED TRUE SKIP_CLANG_TIDY ON)

# fptn-client-cli
add_executable(
  "${PROJECT_NAME}-cli"
  fptn-client-cli.cpp
        vpn/vpn_manager.h
        vpn/vpn_manager.cpp
  vpn/http/client.h
  vpn/http/client.cpp
  routing/route_manager.h
  routing/route_manager.cpp
  socks/socks5_server.cpp
  socks/udp_associate.cpp
  config/config_file.cpp
  config/config_file.h
  plugins/split/tunneling.h
  plugins/split/tunneling.cpp
  plugins/blacklist/domain_blacklist.h
  plugins/blacklist/domain_blacklist.cpp
  ${ADBLOCK_SOURCES}
  "${SPLIT_TUNNEL_GENERATED}"
  utils/speed_estimator/speed_estimator.cpp
  utils/speed_estimator/speed_estimator.h
  utils/speed_estimator/server_info.h
  status/server_registry.cpp
  status/server_registry.h
  status/status_server.cpp
  status/status_server.h)

target_link_libraries(
  "${PROJECT_NAME}-cli"
  PRIVATE ZLIB::ZLIB
          Boost::boost
          Boost::random
          Boost::filesystem
          Boost::process
          Boost::locale
          OpenSSL::SSL
          OpenSSL::Crypto
          argparse::argparse
          nlohmann_json::nlohmann_json
          spdlog::spdlog
          fmt::fmt
          libidn2::libidn2
          re2::re2
          fptn-protocol-lib_static
          "${TUNTAP_LIB}"
          "${BROTLI_DEC_LIB}"
          "${BROTLI_COMMON_LIB}")

# fptn-client-gui
if("${FPTN_BUILD_WITH_GUI_CLIENT}")
  # --- disable clang-tidy for QT generated code ---
  set_source_files_properties($<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/qrc_resources.cpp> PROPERTIES SKIP_CLANG_TIDY ON)
  set(DISABLE_TIDY_DIR "${CMAKE_BINARY_DIR}/src/fptn-client")
  file(MAKE_DIRECTORY "${DISABLE_TIDY_DIR}")
  file(
    WRITE "${DISABLE_TIDY_DIR}/.clang-tidy"
    "Checks: '-*,readability-inconsistent-declaration-parameter-name'
WarningsAsErrors: ''
    ")

  find_package(
    Qt6 REQUIRED
    COMPONENTS Core
               Gui
               Widgets
               Network
               LinguistTools
               Concurrent
               CONFIG
    REQUIRED)
  set(CMAKE_AUTOMOC ON)
  set(CMAKE_AUTORCC ON)
  set(CMAKE_AUTOUIC ON)
  set(CMAKE_INCLUDE_CURRENT_DIR ON)

  qt_standard_project_setup()

  set(QRC_FILES gui/resources/resources.qrc)
  qt6_add_resources(PROJECT_RESOURCES ${QRC_FILES})

  set(QT_ADDITIONAL_PARAMS "")
  if(WIN32)
    set(QT_ADDITIONAL_PARAMS WIN32)
  endif()

  set(PLATFORM_SPECIFIC_LIBS "")
  if(APPLE)
    set(PLATFORM_SPECIFIC_LIBS "-framework Security")
  endif()

  # translations
  file(GLOB TRANSLATIONS gui/resources/translations/*.ts)
  set_source_files_properties(${TRANSLATIONS} PROPERTIES OUTPUT_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/gui/resources/translations/")
  qt6_add_translation(TRANSLATIONS_OUT ${TRANSLATIONS})

  add_executable(
    "${PROJECT_NAME}-gui"
    ${QT_ADDITIONAL_PARAMS}
    fptn-client-gui.cpp
          vpn/vpn_manager.h
          vpn/vpn_manager.cpp
    vpn/http/client.h
    vpn/http/client.cpp
    routing/route_manager.h
    routing/route_manager.cpp
    config/config_file.cpp
    config/config_file.h
    gui/tray/tray.h
    gui/tray/tray.cpp
    gui/speedwidget/speedwidget.h
    gui/speedwidget/speedwidget.cpp
    gui/settingswidget/settings.h
    gui/settingswidget/settings.cpp
    gui/settingsmodel/settingsmodel.h
    gui/settingsmodel/settingsmodel.cpp
    gui/tokendialog/tokendialog.h
    gui/tokendialog/tokendialog.cpp
    gui/translations/translations.h
    gui/translations/translations.cpp
    gui/sni_manager/sni_manager.h
    gui/sni_manager/sni_manager.cpp
    gui/sni_autoscan_dialog/sni_autoscan_dialog.h
    gui/sni_autoscan_dialog/sni_autoscan_dialog.cpp
    gui/server_menu_item_widget/server_menu_item_widget.h
    gui/server_menu_item_widget/server_menu_item_widget.cpp
    gui/style/style.h
    gui/style/style.cpp
    gui/autostart/autostart.h
    gui/autoupdate/autoupdate.h
    plugins/split/tunneling.h
    plugins/split/tunneling.cpp
    plugins/blacklist/domain_blacklist.h
    plugins/blacklist/domain_blacklist.cpp
    ${ADBLOCK_SOURCES}
    "${SPLIT_TUNNEL_GENERATED}"
    utils/windows/vpn_conflict.h
    utils/macos/admin.h
    utils/speed_estimator/speed_estimator.cpp
    utils/speed_estimator/speed_estimator.h
    utils/speed_estimator/server_info.h
    ${PROJECT_RESOURCES}
    ${TRANSLATIONS_OUT})

  target_link_libraries(
    "${PROJECT_NAME}-gui"
    PRIVATE ZLIB::ZLIB
            Boost::boost
            Boost::random
            Boost::filesystem
            Boost::process
            Boost::locale
            OpenSSL::SSL
            OpenSSL::Crypto
            argparse::argparse
            spdlog::spdlog
            fmt::fmt
            Qt6::Core
            Qt6::Gui
            Qt6::Widgets
            Qt6::Network
            Qt6::Concurrent
            libidn2::libidn2
            re2::re2
            fptn-protocol-lib_static
            httplib::httplib
            "${TUNTAP_LIB}"
            "${BROTLI_DEC_LIB}"
            "${BROTLI_COMMON_LIB}"
            "${PLATFORM_SPECIFIC_LIBS}")
  set_target_properties("${PROJECT_NAME}-gui" PROPERTIES AUTOMOC ON)
endif()
