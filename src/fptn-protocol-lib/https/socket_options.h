/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

namespace fptn::protocol::https {

// SO_MARK for the client's own sockets, so firewall rules on a router can
// tell them apart from the traffic it forwards. 0 disables marking.
void SetRoutingMark(std::uint32_t mark) noexcept;

std::uint32_t GetRoutingMark() noexcept;

// Must be called before connect(), or the SYN leaves unmarked.
bool ApplyRoutingMark(int fd) noexcept;

// Connect with the mark already set. The stock helpers open the socket
// themselves, leaving no descriptor to mark before the SYN.
boost::asio::ip::tcp::endpoint ConnectMarked(boost::asio::ip::tcp::socket& socket,
    const boost::asio::ip::tcp::resolver::results_type& results,
    boost::system::error_code& ec);

}  // namespace fptn::protocol::https
