/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/status/status_server.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>    // NOLINT(build/include_order)
#include <boost/asio/detached.hpp>    // NOLINT(build/include_order)
#include <boost/asio/use_awaitable.hpp>  // NOLINT(build/include_order)
#include <boost/beast/core.hpp>       // NOLINT(build/include_order)
#include <boost/beast/http.hpp>       // NOLINT(build/include_order)
#include <fmt/format.h>               // NOLINT(build/include_order)
#include <spdlog/spdlog.h>            // NOLINT(build/include_order)

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

namespace fptn::client::status {

namespace {

constexpr int kDefaultDelayTimeoutMs = 5000;
// Below the 15 s HTTP deadline on purpose: a probe that outlives it would
// finish into a connection the client has already given up on.
constexpr int kMaxDelayTimeoutMs = 10000;
constexpr std::size_t kMaxRequestBody = 8 * 1024;
// Pause before retrying an accept that failed: descriptor exhaustion is
// sticky, and an immediate retry turns into a hot loop.
constexpr std::chrono::milliseconds kAcceptBackoff{200};

// Server names and error strings come off the wire, so they may not be valid
// UTF-8 - and dump() throws on those. A single bad byte in one name would
// otherwise silence /proxies and /status for the life of the process.
std::string Serialize(const nlohmann::json& value) {
  return value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

// plus_as_space belongs to form encoding, that is to the query string only:
// in a path a plus is a literal plus, and a server whose name contains one
// would otherwise be unreachable.
// Only the loopback and the address the endpoint was bound to are accepted:
// this is what stops a rebound domain from reaching the API as its own origin.
bool HostMatches(const std::string& host, const std::string& expected) {
  if (host == expected) {
    return true;
  }
  const auto colon = host.rfind(':');
  return colon != std::string::npos && host.substr(0, colon) == expected;
}

std::string UrlDecode(const std::string& value, bool plus_as_space) {
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      const auto high = static_cast<unsigned char>(value[i + 1]);
      const auto low = static_cast<unsigned char>(value[i + 2]);
      // from_chars would happily take a leading minus, so the digits are
      // checked first: %-1 must stay a literal, not become 0xFF.
      if (std::isxdigit(high) != 0 && std::isxdigit(low) != 0) {
        int code = 0;
        const auto* first = value.data() + i + 1;
        const auto [ptr, ec] = std::from_chars(first, first + 2, code, 16);
        if (ec == std::errc() && ptr == first + 2) {
          out.push_back(static_cast<char>(code));
          i += 2;
          continue;
        }
      }
    }
    if (plus_as_space && value[i] == '+') {
      out.push_back(' ');
      continue;
    }
    out.push_back(value[i]);
  }
  return out;
}

std::string QueryParam(const std::string& query, const std::string& key) {
  std::size_t pos = 0;
  while (pos < query.size()) {
    const auto amp = query.find('&', pos);
    const auto piece = query.substr(
        pos, amp == std::string::npos ? std::string::npos : amp - pos);
    const auto eq = piece.find('=');
    if (eq != std::string::npos && piece.substr(0, eq) == key) {
      return UrlDecode(piece.substr(eq + 1), true);
    }
    if (amp == std::string::npos) {
      break;
    }
    pos = amp + 1;
  }
  return {};
}

}  // namespace

StatusServer::StatusServer(
    Options options, std::shared_ptr<ServerRegistry> registry)
    : options_(std::move(options)), registry_(std::move(registry)) {}

StatusServer::~StatusServer() { Stop(); }

void StatusServer::SetDelayProbe(DelayProbe probe) {
  const std::lock_guard<std::mutex> lock(callbacks_mutex_);
  delay_probe_ = std::move(probe);
}

void StatusServer::SetSwitchServer(SwitchServer handler) {
  const std::lock_guard<std::mutex> lock(callbacks_mutex_);
  switch_server_ = std::move(handler);
}

void StatusServer::SetStatusProvider(StatusProvider provider) {
  const std::lock_guard<std::mutex> lock(callbacks_mutex_);
  status_provider_ = std::move(provider);
}

bool StatusServer::Start() {
  const std::lock_guard<std::mutex> lock(lifecycle_mutex_);
  if (running_) {
    return true;
  }
  // A context that was stopped returns from run() at once, so without this a
  // restarted server would bind, listen and answer nothing - connections
  // would pile up in the backlog instead of being refused.
  ioc_.restart();
  try {
    const auto address =
        boost::asio::ip::make_address(options_.listen_address);
    // Off the loopback the pool, the delay probe and the switch endpoint are
    // on the network, and the secret is the only thing in front of them.
    // Coming up wide open there would be worse than not coming up at all.
    if (!address.is_loopback() && options_.secret.empty()) {
      SPDLOG_ERROR(
          "Status API: refusing to listen on {} without --status-secret - "
          "an endpoint off the loopback has nothing else guarding it",
          options_.listen_address);
      return false;
    }
    const tcp::endpoint endpoint{address, options_.listen_port};

    acceptor_ = std::make_unique<tcp::acceptor>(ioc_);
    acceptor_->open(endpoint.protocol());
    acceptor_->set_option(boost::asio::socket_base::reuse_address(true));
    acceptor_->bind(endpoint);
    acceptor_->listen(boost::asio::socket_base::max_listen_connections);
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Status API: cannot listen on {}:{} - {}",
        options_.listen_address, options_.listen_port, ex.what());
    acceptor_.reset();
    return false;
  }

  running_ = true;
  boost::asio::co_spawn(ioc_, AcceptLoop(), boost::asio::detached);
  threads_.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    threads_.emplace_back([this] { ioc_.run(); });
  }

  SPDLOG_INFO("Status API is listening on {}:{}{}", options_.listen_address,
      options_.listen_port,
      options_.secret.empty() ? " (no token required)" : "");
  return true;
}

void StatusServer::Stop() {
  const std::lock_guard<std::mutex> lock(lifecycle_mutex_);
  if (!running_.exchange(false)) {
    return;
  }
  ioc_.stop();
  for (auto& thread : threads_) {
    // A callback may call Stop() from inside the context: joining the calling
    // thread would throw, and the cleanup below would then be skipped.
    if (thread.get_id() == std::this_thread::get_id()) {
      thread.detach();
      continue;
    }
    if (thread.joinable()) {
      thread.join();
    }
  }
  threads_.clear();
  // Only now, with no thread left in the context: the acceptor is read from
  // the accept coroutine.
  acceptor_.reset();
}

boost::asio::awaitable<void> StatusServer::AcceptLoop() {
  boost::asio::steady_timer backoff(co_await boost::asio::this_coro::executor);
  while (running_) {
    boost::system::error_code ec;
    // The connection is accepted onto its own strand: beast streams are not
    // thread-safe, and the stream keeps its deadline timer running alongside
    // the read, so two threads could otherwise touch one stream at once.
    auto strand = boost::asio::make_strand(ioc_);
    auto socket = co_await acceptor_->async_accept(
        strand, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      if (!running_ || ec == boost::asio::error::operation_aborted) {
        co_return;
      }
      // Out of descriptors is a sticky error: retrying at once spins the CPU
      // and floods the log, which is exactly how the helper once burned a
      // router. Wait a little and say so once.
      SPDLOG_WARN("Status API: accept failed - {}", ec.message());
      backoff.expires_after(kAcceptBackoff);
      co_await backoff.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      continue;
    }
    // Each request gets its own coroutine, on the strand it was accepted on:
    // a slow one must not hold up the rest of the API.
    boost::asio::co_spawn(strand, HandleConnection(std::move(socket)),
        [](std::exception_ptr error) {
          // co_spawn with detached swallows exceptions without a trace; the
          // request is already lost, but the reason must not be.
          if (!error) {
            return;
          }
          try {
            std::rethrow_exception(error);
          } catch (const std::exception& ex) {
            SPDLOG_ERROR("Status API: request failed - {}", ex.what());
          } catch (...) {  // NOLINT
            SPDLOG_ERROR("Status API: request failed with an unknown error");
          }
        });
  }
  co_return;
}

bool StatusServer::HostAllowed(const std::string& host) const {
  if (host.empty()) {
    return true;  // HTTP/1.0 clients may omit it
  }
  // The check is there to stop a page whose domain resolves to the loopback
  // from reaching an endpoint that asks for nothing. Once a secret is set it
  // buys no safety - the request still has to carry the token, and no CORS
  // header goes back, so a browser cannot read the answer either way - while
  // it does break the case it was never meant to cover: an endpoint bound to
  // a LAN address, or to the wildcard, reached by whatever name the caller
  // happened to use.
  if (!options_.secret.empty()) {
    return true;
  }
  return HostMatches(host, "127.0.0.1") || HostMatches(host, "localhost") ||
         HostMatches(host, "[::1]") ||
         HostMatches(host, options_.listen_address);
}

bool StatusServer::Authorized(const std::string& header) const {
  if (options_.secret.empty()) {
    return true;
  }
  constexpr std::string_view kPrefix = "Bearer ";
  if (!header.starts_with(kPrefix)) {
    return false;
  }
  // Compared without an early exit: the endpoint can be bound to something
  // other than the loopback, and then the secret is the only thing guarding
  // it.
  const auto given = header.substr(kPrefix.size());
  if (given.size() != options_.secret.size()) {
    return false;
  }
  unsigned diff = 0;
  for (std::size_t i = 0; i < given.size(); ++i) {
    diff |= static_cast<unsigned char>(given[i]) ^
            static_cast<unsigned char>(options_.secret[i]);
  }
  return diff == 0;
}

boost::asio::awaitable<void> StatusServer::HandleConnection(
    tcp::socket socket) {
  beast::tcp_stream stream(std::move(socket));
  // The deadline only applies to asynchronous operations, which is why the
  // reads and writes below are async: a client that connects and says nothing
  // used to hold the endpoint forever.
  stream.expires_after(std::chrono::seconds(15));

  beast::flat_buffer buffer;
  http::request_parser<http::string_body> parser;
  parser.body_limit(kMaxRequestBody);

  boost::system::error_code ec;
  co_await http::async_read(stream, buffer, parser,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    // A body over the limit deserves an answer: a bare disconnect is
    // indistinguishable from a dead server.
    if (ec == http::error::body_limit) {
      http::response<http::string_body> too_large;
      too_large.result(http::status::payload_too_large);
      too_large.set(http::field::content_type, "application/json");
      too_large.keep_alive(false);
      too_large.body() =
          Serialize(nlohmann::json{{"message", "Body too large"}});
      too_large.prepare_payload();
      co_await http::async_write(stream, too_large,
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      stream.socket().shutdown(tcp::socket::shutdown_send, ec);
    }
    co_return;
  }
  const auto request = parser.release();

  http::response<http::string_body> response;
  response.version(request.version());
  response.set(http::field::content_type, "application/json");
  response.keep_alive(false);

  // CORS is not an authentication mechanism and was never holding anything
  // back here: a page that wants to read the pool still needs the token, and
  // one that is rebound to the loopback bypasses CORS entirely. Withholding
  // the header only kept browsers out - dashboards could not reach the API at
  // all once a secret was set, and the preflight below failed with it. This is
  // what sing-box and mihomo send, so existing dashboards work unchanged.
  response.set(http::field::access_control_allow_origin, "*");
  if (!HostAllowed(std::string(request[http::field::host]))) {
    response.result(http::status::misdirected_request);
    response.body() = Serialize(nlohmann::json{{"message", "Bad host"}});
    response.prepare_payload();
    co_await http::async_write(stream, response,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    stream.socket().shutdown(tcp::socket::shutdown_send, ec);
    co_return;
  }

  // The preflight carries no Authorization header by definition, so it is
  // answered before the check - otherwise a browser could never reach the API
  // with a secret set.
  if (request.method() == http::verb::options) {
    response.result(http::status::no_content);
    response.set(
        http::field::access_control_allow_methods, "GET, PUT, OPTIONS");
    response.set(http::field::access_control_allow_headers,
        "Content-Type, Authorization");
    response.set(http::field::access_control_max_age, "600");
    // Chrome asks before letting a page on a public origin reach a private
    // address, which is every useful case here - the endpoint lives on a LAN
    // address or on the loopback. Answering yes is only sound while the token
    // is what decides, so an endpoint that asks for nothing keeps saying no.
    if (!options_.secret.empty() &&
        !request["Access-Control-Request-Private-Network"].empty()) {
      response.set("Access-Control-Allow-Private-Network", "true");
    }
    response.erase(http::field::content_type);
    response.body().clear();
    response.prepare_payload();
    response.erase(http::field::content_length);
    co_await http::async_write(stream, response,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    stream.socket().shutdown(tcp::socket::shutdown_send, ec);
    co_return;
  }

  const auto auth = std::string(request[http::field::authorization]);
  if (!Authorized(auth)) {
    response.result(http::status::unauthorized);
    response.body() = Serialize(nlohmann::json{{"message", "Unauthorized"}});
  } else {
    try {
      const auto reply = Route(std::string(request.method_string()),
          std::string(request.target()), request.body());
      response.result(static_cast<http::status>(reply.status));
      response.body() = Serialize(reply.body);
    } catch (const std::exception& ex) {
      // Without this the request would end as a bare disconnect: a handler
      // throwing leaves the caller with nothing to read and nothing to go on.
      SPDLOG_ERROR("Status API: {} {} failed - {}", request.method_string(),
          request.target(), ex.what());
      response.result(http::status::internal_server_error);
      response.body() = Serialize(
          nlohmann::json{{"message", "Internal error"}});
    }
  }

  if (response.result_int() == 204 || response.result_int() == 304) {
    response.body().clear();
  }
  response.prepare_payload();
  co_await http::async_write(stream, response,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  stream.socket().shutdown(tcp::socket::shutdown_send, ec);
  co_return;
}

StatusServer::Reply StatusServer::HandleDelay(
    const std::string& name, const std::string& query) const {
  const auto server = registry_->FindByName(name);
  if (!server) {
    return Reply{404, nlohmann::json{{"message", "Resource not found"}}};
  }
  DelayProbe probe;
  {
    const std::lock_guard<std::mutex> lock(callbacks_mutex_);
    probe = delay_probe_;
  }
  if (!probe) {
    return Reply{
        503, nlohmann::json{{"message", "Delay probe is not available"}}};
  }

  int timeout_ms = kDefaultDelayTimeoutMs;
  if (const auto raw = QueryParam(query, "timeout"); !raw.empty()) {
    int parsed = 0;
    const auto [ptr, ec] =
        std::from_chars(raw.data(), raw.data() + raw.size(), parsed);
    if (ec != std::errc() || ptr != raw.data() + raw.size() || parsed <= 0) {
      return Reply{400, nlohmann::json{{"message", "Body invalid"}}};
    }
    // In the Clash API this field is parsed as int16, so timeout=60000
    // silently returns 400. Here it is simply clamped.
    timeout_ms = std::min(parsed, kMaxDelayTimeoutMs);
  }

  const auto delay = probe(*server, timeout_ms);
  // An on-demand probe lands in the window as well: otherwise a manual check
  // leaves nothing behind and the next reader sees a stale number.
  registry_->RecordProbe(
      *server, delay, delay == 0 ? "delay probe failed" : "");
  if (delay == 0) {
    return Reply{503,
        nlohmann::json{{"message", "An error occurred in the delay test"}}};
  }
  return Reply{200, nlohmann::json{{"delay", delay}}};
}

StatusServer::Reply StatusServer::HandleSwitch(
    const std::string& name, const std::string& body) const {
  std::string wanted = name;
  // Clash puts the name in the body: PUT /proxies/<group> {"name": "<node>"}.
  if (!body.empty()) {
    try {
      const auto parsed = nlohmann::json::parse(body);
      if (parsed.contains("name")) {
        wanted = parsed["name"].get<std::string>();
      }
    } catch (const std::exception&) {
      return Reply{400, nlohmann::json{{"message", "Body invalid"}}};
    }
  }

  const auto server = registry_->FindByName(wanted);
  if (!server) {
    return Reply{404, nlohmann::json{{"message", "Resource not found"}}};
  }
  SwitchServer handler;
  {
    const std::lock_guard<std::mutex> lock(callbacks_mutex_);
    handler = switch_server_;
  }
  if (!handler) {
    return Reply{
        503, nlohmann::json{{"message", "Switching is not available"}}};
  }
  if (!handler(*server)) {
    return Reply{
        503, nlohmann::json{{"message", "Server switch was refused"}}};
  }
  // Clash answers a switch with 204, but an empty body is unusual in this
  // API, and the caller benefits from seeing where it actually switched.
  return Reply{
      200, nlohmann::json{{"now", ServerRegistry::DisplayName(*server)}}};
}

StatusServer::Reply StatusServer::Route(const std::string& method,
    const std::string& target,
    const std::string& body) const {
  const auto question = target.find('?');
  const auto path =
      question == std::string::npos ? target : target.substr(0, question);
  const auto query = question == std::string::npos
                         ? std::string{}
                         : target.substr(question + 1);

  if (method == "GET" && (path == "/" || path == "/version")) {
    return Reply{200,
        nlohmann::json{{"version", FPTN_VERSION}, {"hello", "fptn"}}};
  }

  if (method == "GET" && path == "/proxies") {
    return Reply{200, registry_->ToClashProxies()};
  }

  if (method == "GET" && path == "/status") {
    auto payload = registry_->ToJson();
    StatusProvider provider;
    {
      const std::lock_guard<std::mutex> lock(callbacks_mutex_);
      provider = status_provider_;
    }
    if (provider) {
      payload.update(provider());
    }
    return Reply{200, std::move(payload)};
  }

  constexpr std::string_view kProxies = "/proxies/";
  if (path.starts_with(kProxies)) {
    auto rest = path.substr(kProxies.size());
    const bool wants_delay = rest.ends_with("/delay");
    if (wants_delay) {
      rest = rest.substr(0, rest.size() - std::string_view("/delay").size());
    }
    const auto name = UrlDecode(rest, false);

    if (method == "GET" && wants_delay) {
      return HandleDelay(name, query);
    }
    if (method == "PUT" && !wants_delay) {
      return HandleSwitch(name, body);
    }
    if (method == "GET") {
      const auto proxies = registry_->ToClashProxies()["proxies"];
      if (proxies.contains(name)) {
        return Reply{200, proxies[name]};
      }
      return Reply{404, nlohmann::json{{"message", "Resource not found"}}};
    }
  }

  return Reply{404, nlohmann::json{{"message", "Resource not found"}}};
}

}  // namespace fptn::client::status
