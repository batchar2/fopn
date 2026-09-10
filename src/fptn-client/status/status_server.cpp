/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/status/status_server.h"

#include <algorithm>
#include <charconv>
#include <memory>
#include <string>
#include <utility>
#include <vector>

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
constexpr int kMaxDelayTimeoutMs = 60000;
constexpr std::size_t kMaxRequestBody = 8 * 1024;

std::string UrlDecode(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size(); ++i) {
    if (value[i] == '%' && i + 2 < value.size()) {
      int code = 0;
      const auto* first = value.data() + i + 1;
      const auto [ptr, ec] = std::from_chars(first, first + 2, code, 16);
      if (ec == std::errc() && ptr == first + 2) {
        out.push_back(static_cast<char>(code));
        i += 2;
        continue;
      }
    }
    if (value[i] == '+') {
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
      return UrlDecode(piece.substr(eq + 1));
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
  delay_probe_ = std::move(probe);
}

void StatusServer::SetSwitchServer(SwitchServer handler) {
  switch_server_ = std::move(handler);
}

void StatusServer::SetStatusProvider(StatusProvider provider) {
  status_provider_ = std::move(provider);
}

bool StatusServer::Start() {
  if (running_) {
    return true;
  }
  try {
    const auto address =
        boost::asio::ip::make_address(options_.listen_address);
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
  thread_ = std::thread([this] { AcceptLoop(); });

  SPDLOG_INFO("Status API is listening on {}:{}{}", options_.listen_address,
      options_.listen_port,
      options_.secret.empty() ? " (no token required)" : "");
  return true;
}

void StatusServer::Stop() {
  if (!running_.exchange(false)) {
    return;
  }
  boost::system::error_code ec;
  if (acceptor_) {
    acceptor_->close(ec);
  }
  ioc_.stop();
  if (thread_.joinable()) {
    thread_.join();
  }
  acceptor_.reset();
}

void StatusServer::AcceptLoop() {
  while (running_) {
    boost::system::error_code ec;
    tcp::socket socket(ioc_);
    acceptor_->accept(socket, ec);
    if (ec) {
      if (!running_) {
        return;
      }
      // Единичная ошибка приёма не повод ронять весь эндпоинт.
      continue;
    }
    try {
      HandleConnection(std::move(socket));
    } catch (const std::exception& ex) {
      SPDLOG_DEBUG("Status API: request failed - {}", ex.what());
    }
  }
}

bool StatusServer::Authorized(const std::string& header) const {
  if (options_.secret.empty()) {
    return true;
  }
  constexpr std::string_view kPrefix = "Bearer ";
  if (!header.starts_with(kPrefix)) {
    return false;
  }
  return header.substr(kPrefix.size()) == options_.secret;
}

void StatusServer::HandleConnection(tcp::socket socket) {
  beast::tcp_stream stream(std::move(socket));
  stream.expires_after(std::chrono::seconds(15));

  beast::flat_buffer buffer;
  http::request_parser<http::string_body> parser;
  parser.body_limit(kMaxRequestBody);

  boost::system::error_code ec;
  http::read(stream, buffer, parser, ec);
  if (ec) {
    return;
  }
  const auto request = parser.release();

  http::response<http::string_body> response;
  response.version(request.version());
  response.set(http::field::content_type, "application/json");
  response.set(http::field::access_control_allow_origin, "*");
  response.keep_alive(false);

  const auto auth = std::string(request[http::field::authorization]);
  if (!Authorized(auth)) {
    response.result(http::status::unauthorized);
    response.body() = nlohmann::json{{"message", "Unauthorized"}}.dump();
  } else {
    const auto reply = Route(std::string(request.method_string()),
        std::string(request.target()), request.body());
    response.result(static_cast<http::status>(reply.status));
    response.body() = reply.body.dump();
  }

  response.prepare_payload();
  http::write(stream, response, ec);
  stream.socket().shutdown(tcp::socket::shutdown_send, ec);
}

StatusServer::Reply StatusServer::HandleDelay(
    const std::string& name, const std::string& query) const {
  const auto server = registry_->FindByName(name);
  if (!server) {
    return Reply{404, nlohmann::json{{"message", "Resource not found"}}};
  }
  if (!delay_probe_) {
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
    // В Clash API это поле разбирается как int16, и timeout=60000 молча даёт
    // 400. Здесь просто ограничиваем сверху.
    timeout_ms = std::min(parsed, kMaxDelayTimeoutMs);
  }

  const auto delay = delay_probe_(*server, timeout_ms);
  // Замер по запросу тоже попадает в окно: иначе ручная проверка ничего не
  // оставляет после себя, и следующий читатель видит устаревшее число.
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
  // Clash кладёт имя в тело: PUT /proxies/<группа> {"name": "<узел>"}.
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
  if (!switch_server_) {
    return Reply{
        503, nlohmann::json{{"message", "Switching is not available"}}};
  }
  if (!switch_server_(*server)) {
    return Reply{
        503, nlohmann::json{{"message", "Server switch was refused"}}};
  }
  return Reply{204, nlohmann::json::object()};
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
    if (status_provider_) {
      payload.update(status_provider_());
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
    const auto name = UrlDecode(rest);

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
