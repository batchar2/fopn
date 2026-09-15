/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/socket_options.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)
#include <zlib.h>           // NOLINT(build/include_order)

#include "common/network/utils.h"

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4996)
#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#pragma warning(disable : 4702)
#endif

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/detail/openssl_types.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/nowide/convert.hpp>
#include <camouflage/tls/builder.hpp>

#include "common/network/resolv.h"

#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"
#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "fptn-protocol-lib/https/utils/change_cipher_spec.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"

#ifdef _WIN32
#pragma warning(pop)
#endif

namespace {

// ConnectStream keeps the stock connect for the default path and, when a
// routing mark is configured, opens and marks the socket first so the kernel's
// route lookup sees the mark.
template <typename Stream>
boost::asio::ip::tcp::endpoint ConnectStream(
    Stream& stream, const boost::asio::ip::tcp::resolver::results_type& results) {
  if (fptn::protocol::https::GetRoutingMark() == 0) {
    return boost::beast::get_lowest_layer(stream).connect(results);
  }
  boost::system::error_code ec;
  auto& socket = boost::beast::get_lowest_layer(stream).socket();
  const auto endpoint =
      fptn::protocol::https::ConnectMarked(socket, results, ec);
  if (ec) {
    throw boost::system::system_error(ec);
  }
  return endpoint;
}

bool IsPortOpen(const std::string& host, const int port) {
  constexpr std::chrono::milliseconds kConnectTimeout{1500};
  try {
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket socket(ioc);
    socket.open(boost::asio::ip::tcp::v4());
    fptn::protocol::https::ApplyRoutingMark(socket.native_handle());

    boost::asio::ip::tcp::endpoint endpoint;
    boost::system::error_code addr_ec;
    const auto addr = boost::asio::ip::make_address(host, addr_ec);
    if (!addr_ec) {
      endpoint = boost::asio::ip::tcp::endpoint(
          addr, static_cast<boost::asio::ip::port_type>(port));
    } else {
      boost::asio::ip::tcp::resolver resolver(ioc);
      const auto results = resolver.resolve(host, std::to_string(port));
      endpoint = *results.begin();
    }

    boost::asio::steady_timer timer(ioc);
    timer.expires_after(kConnectTimeout);

    bool operation_completed = false;
    bool connected = false;

    socket.async_connect(
        endpoint, [&](const boost::system::error_code& ec) {
          if (!operation_completed) {
            operation_completed = true;
            connected = !ec;
            timer.cancel();
          }
        });

    timer.async_wait([&](const boost::system::error_code& ec) {
      if (!ec && !operation_completed) {
        operation_completed = true;
        connected = false;
        boost::system::error_code close_ec;
        socket.close(close_ec);
      }
    });

    ioc.restart();
    while (!operation_completed) {
      ioc.run_one();
    }

    if (socket.is_open()) {
      boost::system::error_code close_ec;
      socket.close(close_ec);
    }
    return connected;
  } catch (...) {
    return false;
  }
}

std::string DecompressGzip(const std::string& compressed) {
  constexpr std::size_t kChunkSize = 4096;

  std::vector<char> buffer(kChunkSize);

  ::z_stream strm{};
  strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
  strm.avail_in = static_cast<unsigned int>(compressed.size());

  if (::inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
    return {};
  }

  std::string decompressed;
  int ret = 0;
  do {
    strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
    strm.avail_out = static_cast<unsigned int>(buffer.size());
    ret = inflate(&strm, Z_NO_FLUSH);

    if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
      inflateEnd(&strm);
      return {};
    }
    decompressed.append(buffer.data(), buffer.size() - strm.avail_out);
  } while (ret != Z_STREAM_END);

  inflateEnd(&strm);
  return decompressed;
}

std::string GetHttpBody(
    const boost::beast::http::response<boost::beast::http::dynamic_body>& res) {
  auto body = boost::beast::buffers_to_string(res.body().data());
  if (res[boost::beast::http::field::content_encoding] == "gzip") {
    return DecompressGzip(body);
  }
  return body;
}

void SetSocketTimeouts(
    boost::asio::ip::tcp::socket& socket, int timeout_seconds) {
  auto native_socket = socket.native_handle();

#ifdef _WIN32
  DWORD timeout_ms = timeout_seconds * 1000;
  ::setsockopt(native_socket, SOL_SOCKET, SO_RCVTIMEO,
      reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
  ::setsockopt(native_socket, SOL_SOCKET, SO_SNDTIMEO,
      reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
  timeval tv = {};
  tv.tv_sec = timeout_seconds;
  tv.tv_usec = 0;
  ::setsockopt(native_socket, SOL_SOCKET, SO_RCVTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
  ::setsockopt(native_socket, SOL_SOCKET, SO_SNDTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

using Headers = std::unordered_map<std::string, std::string>;

Headers RealBrowserHeaders() {
  /* Just to ensure that FPTN is as similar to a web browser as possible. */
#ifdef __linux__  // chromium ubuntu arm
  return {{"User-Agent",
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
              "Gecko) Chrome/134.0.0.0 Safari/537.36"},
      {"Accept-Language", "en-US,en;q=0.9"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br, zstd"},
      {"Sec-Ch-Ua", R"("Not:A-Brand";v="24", "Chromium";v="134")"},
      {"Sec-Ch-Ua-Mobile", "?0"}, {"Sec-Ch-Ua-Platform", R"("Linux")"},
      {"Upgrade-Insecure-Requests", "1"}, {"Sec-Fetch-Site", "cross-site"},
      {"Sec-Fetch-Mode", "navigate"}, {"Sec-Fetch-User", "?1"},
      {"Sec-Fetch-Dest", "document"}, {"Priority", "u=0, i"}};
#elif __APPLE__
  // apple silicon chrome
  return {
      {"sec-ch-ua",
          R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
      {"sec-ch-ua-platform", "\"macOS\""}, {"sec-ch-ua-mobile", "?0"},
      {"upgrade-insecure-requests", "1"},
      {"User-Agent",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"sec-fetch-site", "none"}, {"sec-fetch-mode", "no-cors"},
      {"sec-fetch-dest", "empty"}, {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br"},
      {"Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
      {"priority", "u=4, i"}};
#elif _WIN32
  // chrome windows amd64
  return {
      {"sec-ch-ua",
          R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
      {"sec-ch-ua-mobile", "?0"}, {"sec-ch-ua-platform", "\"Windows\""},
      {"upgrade-insecure-requests", "1"},
      {"User-Agent",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"sec-fetch-site", "cross-site"}, {"sec-fetch-mode", "navigate"},
      {"sec-fetch-user", "?1"}, {"sec-fetch-dest", "document"},
      {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br, zstd"},
      {"Accept-Language", "en-US,en;q=0.9,ru;q=0.8"}, {"priority", "u=0, i"}};
#else
#error Undefined platform
#endif
}

template <typename TResult>
TResult ExecuteWithTimeout(const std::function<TResult()>& operation,
    int timeout,
    const std::string& operation_name,
    const std::string& handle,
    const std::string& host,
    const TResult& timeout_result) {
  try {
    // Shared state
    struct SharedState {
      std::mutex mutex;
      std::condition_variable cv;
      bool ready = false;
      TResult result;
      std::atomic<bool> cancelled{false};
    };

    const auto start_time = std::chrono::steady_clock::now();

    auto state = std::make_shared<SharedState>();

    // NOLINTNEXTLINE(bugprone-exception-escape)
    std::weak_ptr<SharedState> weak_state = state;
    std::thread([weak_state, operation]() {
      TResult impl_result = operation();
      // check state
      if (auto state = weak_state.lock()) {
        const std::scoped_lock<std::mutex> lock(state->mutex);
        if (!state->cancelled) {
          state->result = impl_result;
          state->ready = true;
          state->cv.notify_one();
        }
      }
    }).detach();

    std::unique_lock<std::mutex> lock(state->mutex);  // mutex
    if (!state->cv.wait_for(lock, std::chrono::seconds(timeout),
            [state]() { return state->ready; })) {
      const auto end_time = std::chrono::steady_clock::now();
      const auto duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              end_time - start_time);

      state->cancelled = true;

      SPDLOG_WARN("{} [{}] - Timeout after {} ms for server {}", operation_name,
          handle, duration.count(), host);
      return timeout_result;
    }
    return state->result;
  } catch (...) {
    SPDLOG_ERROR("Undefined error: {} {}", operation_name, handle);
  }
  return timeout_result;
}

};  // namespace

namespace fptn::protocol::https {

using tcp_stream_type = boost::beast::tcp_stream;
using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;

ApiClient::ApiClient(
    const std::string& host, int port, CensorshipStrategy censorship_strategy)
    : host_(host),
      port_(port),
      sni_(host),
      censorship_strategy_(censorship_strategy) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    CensorshipStrategy censorship_strategy)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      censorship_strategy_(censorship_strategy) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    std::string md5_fingerprint,
    CensorshipStrategy censorship_strategy)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      expected_md5_fingerprint_(std::move(md5_fingerprint)),
      censorship_strategy_(censorship_strategy) {}  // NOLINT

Response ApiClient::Get(const std::string& handle, int timeout) const {
  // NOLINTNEXTLINE(bugprone-exception-escape)
  return ExecuteWithTimeout<Response>(
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [self = *this, handle, timeout]() {
        if (!IsPortOpen(self.host_, self.port_)) {
          SPDLOG_ERROR("GET [{}] - port {}:{} is not reachable", handle,
              self.host_, self.port_);
          return Response{"", 609, "Port not reachable"};
        }
        return self.GetImpl(handle, timeout);
      },
      timeout, "GET", handle, host_, Response{"", 608, "Operation timeout"});
}

Response ApiClient::Post(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) const {
  // NOLINTNEXTLINE(bugprone-exception-escape)
  return ExecuteWithTimeout<Response>(
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [self = *this, handle, request, content_type, timeout]() {
        if (!IsPortOpen(self.host_, self.port_)) {
          SPDLOG_ERROR("POST [{}] - port {}:{} is not reachable", handle,
              self.host_, self.port_);
          return Response{"", 609, "Port not reachable"};
        }
        return self.PostImpl(handle, request, content_type, timeout);
      },
      timeout, "POST", handle, host_, Response{"", 608, "Operation timeout"});
}

boost::asio::awaitable<Response> ApiClient::AsyncPost(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) const {
  const auto start_time = std::chrono::steady_clock::now();
  std::string error;
  int respcode = 400;
  std::string body;

  auto executor = co_await boost::asio::this_coro::executor;

  auto* ssl_ctx_raw = utils::CreateNewSslCtx();
  boost::asio::ssl::context ctx(ssl_ctx_raw);

  fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr;
  if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
    obfuscator =
        std::make_shared<protocol::https::obfuscator::TlsObfuscator2>();
  }

  tcp_stream_type tcp_stream(executor);
  obfuscator_socket_type obfuscator_stream(std::move(tcp_stream), obfuscator);
  ssl_stream_type stream(std::move(obfuscator_stream), ctx);

  boost::beast::get_lowest_layer(stream).expires_after(
      std::chrono::seconds(timeout));

  try {
    const std::string port_str = std::to_string(port_);
    boost::system::error_code ec;

    boost::asio::ip::tcp::resolver::results_type results;
    if (const auto addr = boost::asio::ip::make_address(host_, ec); !ec) {
      results = boost::asio::ip::tcp::resolver::results_type::create(
          boost::asio::ip::tcp::endpoint(
              addr, static_cast<boost::asio::ip::port_type>(port_)),
          host_, port_str);
    } else {
      ec.clear();
      boost::asio::ip::tcp::resolver resolver(executor);
      results = co_await resolver.async_resolve(host_, port_str,
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        SPDLOG_ERROR("AsyncPost [{}] - DNS failed for {}:{}: {}", handle, host_,
            port_, ec.message());
        co_return Response{"", 603, ec.message()};
      }
    }

    if (fptn::protocol::https::GetRoutingMark() != 0) {
      // The mark has to be on the socket before the SYN, and a range connect
      // reopens the socket per attempt, which would drop it. So the endpoints
      // are walked by hand - every one of them, because a host with several
      // addresses must keep its fallback. The connect still goes through the
      // beast stream: a raw socket connect ignores the stream deadline, and a
      // blackholed address would then hang on the kernel SYN timeout instead.
      ec = boost::asio::error::host_not_found;
      for (const auto& entry : results) {
        auto& socket = boost::beast::get_lowest_layer(stream).socket();
        boost::system::error_code open_ec;
        socket.open(entry.endpoint().protocol(), open_ec);
        if (open_ec) {
          // Without the mark the tunnel traffic would come back through the
          // tunnel, so an unmarked socket is worse than no connection.
          SPDLOG_ERROR("AsyncPost [{}] - Cannot open a marked socket: {}",
              handle, open_ec.message());
          ec = open_ec;
          // Keep going: a router with no IPv6 route fails to open the AAAA
          // endpoint, and the IPv4 one behind it is exactly the fallback.
          continue;
        }
        fptn::protocol::https::ApplyRoutingMark(socket.native_handle());
        co_await boost::beast::get_lowest_layer(stream).async_connect(
            entry.endpoint(),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (!ec) {
          break;
        }
        boost::system::error_code close_ec;
        socket.close(close_ec);
      }
    } else {
      co_await boost::beast::get_lowest_layer(stream).async_connect(
          results, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    }
    if (ec) {
      SPDLOG_ERROR("AsyncPost [{}] - Connect failed for {}: {}", handle, host_,
          ec.message());
      co_return Response{"", 600, ec.message()};
    }

    utils::SetHandshakeSessionID(stream.native_handle());
    utils::SetHandshakeSni(stream.native_handle(), sni_);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);

    co_await stream.async_handshake(boost::asio::ssl::stream_base::client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("AsyncPost [{}] - TLS handshake failed for {}: {}", handle,
          host_, ec.message());
      co_return Response{"", 600, ec.message()};
    }

    stream.next_layer().set_obfuscator(nullptr);

    boost::beast::http::request<boost::beast::http::string_body> req{
        boost::beast::http::verb::post, handle, 11};
    req.set(boost::beast::http::field::host, host_);
    req.set(boost::beast::http::field::content_type, content_type);
    req.body() = request;
    req.prepare_payload();

    co_await boost::beast::http::async_write(stream, req,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("AsyncPost [{}] - Write failed for {}: {}", handle, host_,
          ec.message());
      co_return Response{"", 600, ec.message()};
    }

    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::dynamic_body> res;
    co_await boost::beast::http::async_read(stream, buffer, res,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("AsyncPost [{}] - Read failed for {}: {}", handle, host_,
          ec.message());
      co_return Response{"", 600, ec.message()};
    }

    respcode = static_cast<int>(res.result_int());
    body = GetHttpBody(res);

    boost::system::error_code shutdown_ec;
    stream.shutdown(shutdown_ec);
  } catch (const boost::system::system_error& err) {
    error = err.what();
    respcode = 600;
    SPDLOG_ERROR(
        "AsyncPost [{}] - System error for {}: {}", handle, host_, error);
  } catch (const std::exception& e) {
    error = e.what();
    respcode = 601;
    SPDLOG_ERROR("AsyncPost [{}] - Exception for {}: {}", handle, host_, error);
  }

  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start_time);

  if (respcode >= 200 && respcode < 300) {
    SPDLOG_INFO(
        "AsyncPost [{}] - Success from {} in {} ms - Status: {}, "
        "Response: {} bytes",
        handle, host_, duration.count(), respcode, body.size());
  } else {
    SPDLOG_WARN(
        "AsyncPost [{}] - Failed from {} in {} ms - Status: {}, Error: {}",
        handle, host_, duration.count(), respcode, error);
  }
  co_return Response{body, respcode, error};
}

bool ApiClient::TestHandshake(int timeout) const {
  // NOLINTNEXTLINE(bugprone-exception-escape)
  return ExecuteWithTimeout<bool>(
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [self = *this, timeout]() {
        if (!IsPortOpen(self.host_, self.port_)) {
          SPDLOG_ERROR("TestHandshake - port {}:{} is not reachable",
              self.host_, self.port_);
          return false;
        }
        return self.TestHandshakeImpl(timeout);
      },
      timeout, "TestHandshake", "", host_, false);
}

ApiClient ApiClient::Clone() const {
  ApiClient temp_client(
      host_, port_, sni_, expected_md5_fingerprint_, censorship_strategy_);
  return temp_client;
}

bool ApiClient::PerformFakeHandshake2(
    boost::asio::ip::tcp::socket& socket) const {
  try {
    SPDLOG_INFO("Fake TLS handshake started for SNI: {}", sni_);

    /* Send client hello */
    const auto client_hello = GenerateHandshakePacket();
    if (client_hello.empty()) {
      SPDLOG_WARN("Failed to generate ClientHello for SNI: {}", sni_);
      return false;
    }
    const std::size_t client_hello_bytes_size =
        boost::asio::write(socket, boost::asio::buffer(client_hello));
    if (client_hello_bytes_size != client_hello.size()) {
      SPDLOG_ERROR("Error ClientHello sent: {} of {} bytes",
          client_hello_bytes_size, client_hello.size());
      return false;
    }

    const auto server_hello = common::network::WaitForServerTlsHello(
        socket, std::chrono::seconds(6));
    if (!server_hello.has_value()) {
      SPDLOG_ERROR("Failed to receive ServerHello from {}", sni_);
      return false;
    }

    /* Send change cipher spec */
    const auto change_cipher_spec =
        fptn::protocol::https::utils::MakeClientChangeCipherSpec();
    const std::size_t change_cipher_spec_size =
        boost::asio::write(socket, boost::asio::buffer(change_cipher_spec));
    if (change_cipher_spec_size != change_cipher_spec.size()) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}",
          change_cipher_spec_size, change_cipher_spec.size());
      return false;
    }

    // timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    SPDLOG_INFO(
        "Fake TLS handshake completed for {}, received {} bytes from server",
        sni_, server_hello.value().size());
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Fake TLS handshake exception for {}: {}", sni_, e.what());
  }
  return false;
}

Response ApiClient::GetImpl(const std::string& handle, int timeout) const {
  std::string body;
  std::string error;
  int respcode = 400;

  const auto start_time = std::chrono::steady_clock::now();

  SSL* ssl = nullptr;
  std::string server_ip;
  try {
    boost::asio::io_context ioc;

    auto* ssl_ctx = fptn::protocol::https::utils::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator =
          std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator2>();
    }

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(std::move(tcp_stream), obfuscator);
    ssl_stream_type stream(std::move(obfuscator_stream), ctx);

    const std::string port_str = std::to_string(port_);
    auto resolve_result = fptn::common::network::ResolveWithTimeout(
        ioc, host_, port_str, timeout);

    if (!resolve_result) {
      error = resolve_result.error.message();
      respcode = 603;
      SPDLOG_ERROR("GET [{}] - DNS resolution failed for {}:{}: {}", handle,
          host_, port_, error);
    } else {
      SPDLOG_INFO("GET [{}] - Connecting to server: {}:{} [strategy={}]",
          handle, host_, port_, ToString(censorship_strategy_));

      boost::beast::get_lowest_layer(stream).expires_after(
          std::chrono::seconds(timeout));
      stream.next_layer().next_layer().expires_after(
          std::chrono::seconds(timeout));

      auto connected_endpoint =
          ConnectStream(stream, resolve_result.results);
      server_ip = connected_endpoint.address().to_string();

      SPDLOG_INFO("GET [{}] - Successfully connected to {}", handle, host_);

      auto& socket = boost::beast::get_lowest_layer(stream).socket();
      SetSocketTimeouts(socket, timeout);

      // Perform fake handshake if enabled
      if (IsRealityModeWithFakeHandshake(censorship_strategy_)) {
        const bool perform_status = PerformFakeHandshake2(socket);
        if (!perform_status) {
          SPDLOG_ERROR(
              "GET [{}] - Fake handshake failed for server {}", handle, host_);
          throw std::runtime_error("Fake handshake failed");
        }
        // For Reality Mode we use TLS obfuscator after fake handshake
        // This provides additional encryption layer for the real connection
        stream.next_layer().set_obfuscator(
            std::make_shared<protocol::https::obfuscator::TlsObfuscator2>());
      }

      utils::SetHandshakeSessionID(stream.native_handle());
      utils::SetHandshakeSni(stream.native_handle(), sni_);
      if (!expected_md5_fingerprint_.empty()) {
        ssl = stream.native_handle();
        utils::AttachCertificateVerificationCallback(
            ssl, [this, &error](const std::string& md5_fingerprint) {
              return onVerifyCertificate(md5_fingerprint, error);
            });
      } else {
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
      }

      stream.handshake(boost::asio::ssl::stream_base::client);

      // Reset obfuscator after TLS-handshake
      stream.next_layer().set_obfuscator(nullptr);

      // timeout
      std::this_thread::sleep_for(std::chrono::milliseconds(150));

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::get, handle, 11};

      // set http headers
      const auto headers = RealBrowserHeaders();
      for (const auto& [key, value] : headers) {
        req.set(key, value);
      }

      boost::beast::http::write(stream, req);

      boost::beast::flat_buffer buffer;
      boost::beast::http::response<boost::beast::http::dynamic_body> res;

      boost::beast::http::read(stream, buffer, res);

      respcode = static_cast<int>(res.result_int());
      body = GetHttpBody(res);

      boost::system::error_code ec;
      stream.shutdown(ec);
      try {
        boost::beast::get_lowest_layer(stream).close();
      } catch (boost::system::system_error const& e) {
        SPDLOG_ERROR(
            "GET [{}] - Exception during connection close for server {}: {}",
            handle, host_, e.what());
      }
    }
  } catch (const boost::system::system_error& err) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error = err.what();
#endif
    respcode = 600;
    SPDLOG_ERROR("GET [{}] - System error for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (const std::exception& e) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error = e.what();
#endif
    respcode = 601;
    SPDLOG_ERROR("GET [{}] - Exception for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (...) {
    error = "Unknown exception";
    respcode = 602;
    SPDLOG_ERROR("GET [{}] - Unknown exception for server {} (IP: {})", handle,
        host_, server_ip);
  }
  if (ssl) {
    utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  const auto end_time = std::chrono::steady_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  if (respcode >= 200 && respcode < 300) {
    SPDLOG_INFO(
        "GET [{}] - Success from server {} (IP: {}) in {} ms - Status: {}, "
        "Body size: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, body.size());
  } else {
    SPDLOG_WARN(
        "GET [{}] - Failed from server {} (IP: {}) in {} ms - Status: {}, "
        "Error: {}, Body size: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, error,
        body.size());
  }
  return {body, respcode, error};
}

Response ApiClient::PostImpl(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) const {
  std::string body;
  std::string error;
  int respcode = 400;

  const auto start_time = std::chrono::steady_clock::now();

  SSL* ssl = nullptr;
  std::string server_ip;

  try {
    boost::asio::io_context ioc;
    auto* ssl_ctx = utils::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator =
          std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator2>();
    }

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(std::move(tcp_stream), obfuscator);
    ssl_stream_type stream(std::move(obfuscator_stream), ctx);

    const std::string port_str = std::to_string(port_);
    auto resolve_result = fptn::common::network::ResolveWithTimeout(
        ioc, host_, port_str, timeout);

    if (!resolve_result) {
      error = resolve_result.error.message();
      respcode = 603;
      SPDLOG_ERROR("POST [{}] - DNS resolution failed for {}:{}: {}", handle,
          host_, port_, error);
    } else {
      SPDLOG_INFO("POST [{}] - Connecting to server: {}:{} [strategy={}]",
          handle, host_, port_, ToString(censorship_strategy_));

      boost::beast::get_lowest_layer(stream).expires_after(
          std::chrono::seconds(timeout));
      stream.next_layer().next_layer().expires_after(
          std::chrono::seconds(timeout));

      auto connected_endpoint =
          ConnectStream(stream, resolve_result.results);
      server_ip = connected_endpoint.address().to_string();

      SPDLOG_INFO("POST [{}] - Successfully connected to {}", handle, host_);

      auto& socket = boost::beast::get_lowest_layer(stream).socket();
      SetSocketTimeouts(socket, timeout);

      // Perform fake handshake if enabled
      if (IsRealityModeWithFakeHandshake(censorship_strategy_)) {
        const bool perform_status = PerformFakeHandshake2(socket);
        if (!perform_status) {
          SPDLOG_ERROR(
              "POST [{}] - Fake handshake failed for server {}", handle, host_);
          throw std::runtime_error("Fake handshake failed");
        }
        // For Reality Mode we use TLS obfuscator after fake handshake
        // This provides additional encryption layer for the real connection
        stream.next_layer().set_obfuscator(
            std::make_shared<protocol::https::obfuscator::TlsObfuscator2>());
      }

      utils::SetHandshakeSessionID(stream.native_handle());
      utils::SetHandshakeSni(stream.native_handle(), sni_);
      if (!expected_md5_fingerprint_.empty()) {
        ssl = stream.native_handle();
        utils::AttachCertificateVerificationCallback(
            ssl, [this, &error](const std::string& md5_fingerprint) {
              return onVerifyCertificate(md5_fingerprint, error);
            });
      } else {
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
      }

      stream.handshake(boost::asio::ssl::stream_base::client);

      // Reset obfuscator after TLS-handshake
      stream.next_layer().set_obfuscator(nullptr);

      // timeout
      std::this_thread::sleep_for(std::chrono::milliseconds(150));

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::post, handle, 11};
      req.set(boost::beast::http::field::host, host_);
      req.set(boost::beast::http::field::accept, "*/*");
      req.set(boost::beast::http::field::content_type, content_type);
      req.set(boost::beast::http::field::content_length,
          std::to_string(request.size()));

      // set http headers
      const auto headers = RealBrowserHeaders();
      for (const auto& [key, value] : headers) {
        req.set(key, value);
      }

      req.body() = request;
      req.prepare_payload();

      boost::beast::http::write(stream, req);

      boost::beast::flat_buffer buffer;
      boost::beast::http::response<boost::beast::http::dynamic_body> res;
      boost::beast::http::read(stream, buffer, res);

      respcode = static_cast<int>(res.result_int());
      body = GetHttpBody(res);

      boost::system::error_code ec;
      stream.shutdown(ec);
      try {
        boost::beast::get_lowest_layer(stream).close();
      } catch (boost::system::system_error const& e) {
        SPDLOG_ERROR(
            "POST [{}] - Exception during connection close for server {}: {}",
            handle, host_, e.what());
      }
    }
  } catch (const boost::system::system_error& err) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error = err.what();
#endif
    respcode = 600;
    SPDLOG_ERROR("POST [{}] - System error for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (const std::exception& e) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error = e.what();
#endif
    respcode = 601;
    SPDLOG_ERROR("POST [{}] - Exception for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (...) {
    error = "Unknown exception";
    respcode = 602;
    SPDLOG_ERROR("POST [{}] - Unknown exception for server {} (IP: {})", handle,
        host_, server_ip);
  }
  if (ssl) {
    utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  const auto end_time = std::chrono::steady_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  if (respcode >= 200 && respcode < 300) {
    SPDLOG_INFO(
        "POST [{}] - Success from server {} (IP: {}) in {} ms - Status: {}, "
        "Request: {} bytes, Response: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, request.size(),
        body.size());
  } else {
    SPDLOG_WARN(
        "POST [{}] - Failed from server {} (IP: {}) in {} ms - Status: {}, "
        "Error: {}, Request: {} bytes, Response: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, error,
        request.size(), body.size());
  }
  return {body, respcode, error};
}

bool ApiClient::TestHandshakeImpl(int timeout) const {
  const auto start_time = std::chrono::steady_clock::now();
  std::string server_ip;
  SSL* ssl = nullptr;

  try {
    boost::asio::io_context ioc;
    auto* ssl_ctx = utils::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator =
          std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator2>();
    }

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(std::move(tcp_stream), obfuscator);
    ssl_stream_type stream(std::move(obfuscator_stream), ctx);

    const std::string port_str = std::to_string(port_);
    auto resolve_result = fptn::common::network::ResolveWithTimeout(
        ioc, host_, port_str, timeout);

    if (!resolve_result) {
      SPDLOG_WARN("TestHandshake - DNS resolution failed for {}:{}: {}", host_,
          port_, resolve_result.error.message());

      const auto end_time = std::chrono::steady_clock::now();
      const auto duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              end_time - start_time);

      SPDLOG_WARN(
          "Handshake failed for server {} in {} ms - DNS resolution error",
          host_, duration.count());
      return false;
    }

    SPDLOG_INFO("TestHandshake - Connecting to server: {}:{} [strategy={}]",
        host_, port_, ToString(censorship_strategy_));

    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    stream.next_layer().next_layer().expires_after(
        std::chrono::seconds(timeout));

    auto connected_endpoint = ConnectStream(stream, resolve_result.results);
    server_ip = connected_endpoint.address().to_string();

    SPDLOG_INFO("TestHandshake - Successfully connected to {} (IP: {})", host_,
        server_ip);

    auto& socket = boost::beast::get_lowest_layer(stream).socket();
    SetSocketTimeouts(socket, timeout);

    // Perform fake handshake if enabled
    if (IsRealityModeWithFakeHandshake(censorship_strategy_)) {
      SPDLOG_INFO("TestHandshake - Performing fake handshake");
      if (!PerformFakeHandshake2(socket)) {
        SPDLOG_WARN(
            "TestHandshake - Fake handshake failed, continuing with real "
            "handshake");
      }
    }
    utils::SetHandshakeSessionID(stream.native_handle());
    utils::SetHandshakeSni(stream.native_handle(), sni_);

    if (!expected_md5_fingerprint_.empty()) {
      ssl = stream.native_handle();
      std::string error;
      utils::AttachCertificateVerificationCallback(
          ssl, [this, &error](const std::string& md5_fingerprint) {
            return onVerifyCertificate(md5_fingerprint, error);
          });
    } else {
      ctx.set_verify_mode(boost::asio::ssl::verify_none);
    }

    // Perform TLS handshake
    stream.handshake(boost::asio::ssl::stream_base::client);

    // Clean shutdown
    boost::system::error_code ec;
    stream.shutdown(ec);

    // Close connection
    boost::beast::get_lowest_layer(stream).close();

    const auto end_time = std::chrono::steady_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    SPDLOG_INFO("Handshake successful for server {} (IP: {}) in {} ms", host_,
        server_ip, duration.count());

    if (ssl) {
      utils::AttachCertificateVerificationCallbackDelete(ssl);
    }
    return true;
  } catch (const boost::system::system_error& err) {
    std::string host_copy = host_;
    std::string server_ip_copy = server_ip;
    std::string error_msg;

#ifdef _WIN32
    error_msg = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error_msg = err.what();
#endif

    SPDLOG_WARN("Handshake failed for server {} (IP: {}): {}", host_copy,
        server_ip_copy, error_msg);
  } catch (const std::exception& e) {
    // Copy the strings before handing them to the logger
    std::string host_copy = host_;
    std::string server_ip_copy = server_ip;
    std::string error_msg;

#ifdef _WIN32
    error_msg = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error_msg = e.what();
#endif

    SPDLOG_WARN("Handshake failed for server {} (IP: {}): {}", host_copy,
        server_ip_copy, error_msg);
  } catch (...) {
    // Copy the strings before handing them to the logger
    std::string host_copy = host_;
    std::string server_ip_copy = server_ip;

    SPDLOG_WARN("Handshake failed for server {} (IP: {}): Unknown exception",
        host_copy, server_ip_copy);
  }

  if (ssl) {
    utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  const auto end_time = std::chrono::steady_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  SPDLOG_WARN("Handshake failed for server {} (IP: {}) in {} ms", host_,
      server_ip, duration.count());

  return false;
}

bool ApiClient::onVerifyCertificate(
    const std::string& md5_fingerprint, std::string& error) const {
  if (expected_md5_fingerprint_.empty()) {
    return true;
  }
  if (md5_fingerprint == expected_md5_fingerprint_) {
    return true;
  }
  error = fmt::format(
      "Certificate MD5 mismatch. Expected: {}, got: {}. "
      "Please update your token.",
      expected_md5_fingerprint_, md5_fingerprint);
  SPDLOG_ERROR(
      "Certificate verification failed for server {}: {}", host_, error);
  return false;
}

std::vector<std::uint8_t> ApiClient::GenerateHandshakePacket() const {
  auto builder = camouflage::tls::Builder::Create();

  switch (censorship_strategy_) {
    /* Chrome */
    case CensorshipStrategy::kSniRealityModeChrome149:
      SPDLOG_INFO("Selected strategy: Chrome 149");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_149_0_7827_103);
      break;
    case CensorshipStrategy::kSniRealityModeChrome148:
      SPDLOG_INFO("Selected strategy: Chrome 148");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_148_0_7778_216);
      break;
    case CensorshipStrategy::kSniRealityModeChrome147:
      SPDLOG_INFO("Selected strategy: Chrome 147");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_147_0_7727_56);
      break;
    case CensorshipStrategy::kSniRealityModeChrome146:
      SPDLOG_INFO("Selected strategy: Chrome 146");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_146_0_7680_178);
      break;
    case CensorshipStrategy::kSniRealityModeChrome145:
      SPDLOG_INFO("Selected strategy: Chrome 145");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_145_0_7632_46);
      break;
      /* Firefox */
    case CensorshipStrategy::kSniRealityModeFirefox151:
      SPDLOG_INFO("Selected strategy: Firefox 151");
      builder.Firefox(camouflage::tls::firefox::Version::kV_151_0_3);
      break;
    case CensorshipStrategy::kSniRealityModeFirefox150:
      SPDLOG_INFO("Selected strategy: Firefox 150");
      builder.Firefox(camouflage::tls::firefox::Version::kV_150_0_3);
      break;
    case CensorshipStrategy::kSniRealityModeFirefox149:
      SPDLOG_INFO("Selected strategy: Firefox 149");
      builder.Firefox(camouflage::tls::firefox::Version::kV_149_0);
      break;
    /* Safari */
    case CensorshipStrategy::kSniRealityModeSafari26_5:
      SPDLOG_INFO("Selected strategy: Safari 26.5");
      builder.Safari(camouflage::tls::safari::Version::kV_26_5);
      break;
    case CensorshipStrategy::kSniRealityModeSafari26_4:
      SPDLOG_INFO("Selected strategy: Safari 26.4");
      builder.Safari(camouflage::tls::safari::Version::kV_26_4);
      break;
    /* Yandex */
    case CensorshipStrategy::kSniRealityModeYandex26_4:
      SPDLOG_INFO("Selected strategy: Yandex 26.4");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_26_4_3_897);
      break;
    case CensorshipStrategy::kSniRealityModeYandex26_3:
      SPDLOG_INFO("Selected strategy: Yandex 26.3");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_26_3_3_881);
      break;
    case CensorshipStrategy::kSniRealityModeYandex25:
      SPDLOG_INFO("Selected strategy: Yandex 25");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_25_8_3_828);
      break;
    case CensorshipStrategy::kSniRealityModeYandex24:
      SPDLOG_INFO("Selected strategy: Yandex 24");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_24_12_0_1772);
      break;
    default:
      SPDLOG_DEBUG("Using fallback handshake generator for SNI: {}", sni_);
      return utils::GenerateDecoyTlsHandshake(sni_);
  }

  SPDLOG_INFO("Generating handshake for SNI: {}", sni_);

  const auto session_id = utils::GenerateDecoyTlsSessionId2();
  if (!session_id.has_value()) {
    SPDLOG_WARN("Session ID generation failed for handshake, using fallback");
    return utils::GenerateDecoyTlsHandshake(sni_);
  }

  const auto handshake =
      builder.SetSNI(sni_).SetSessionId(session_id.value()).Generate();
  if (!handshake.has_value()) {
    SPDLOG_WARN(
        "Handshake generation failed for SNI: {}, using fallback", sni_);
    return utils::GenerateDecoyTlsHandshake(sni_);
  }

  SPDLOG_INFO("Handshake generated: SNI={}, size={} bytes", sni_,
      handshake->handshake_packet_size);
  return std::vector<std::uint8_t>(handshake->handshake_packet,
      handshake->handshake_packet + handshake->handshake_packet_size);
}
}  // namespace fptn::protocol::https
