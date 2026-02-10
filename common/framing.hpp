#pragma once

#include "common/json.hpp"

#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace common {

static constexpr std::size_t kMaxFrameSize = 64 * 1024;

inline void write_u32_be(uint32_t v, uint8_t out[4]) {
  out[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(v & 0xFF);
}

inline uint32_t read_u32_be(const uint8_t in[4]) {
  return (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
         (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
}

// Datagram-friendly helpers: frame/parse a single JSON payload into/from a byte buffer.
// Useful for UDP where reads are already message-bounded.
inline std::optional<std::vector<uint8_t>> frame_json_bytes(const json& j, std::size_t max_len = kMaxFrameSize) {
  const std::string payload = j.dump();
  if (payload.empty() || payload.size() > max_len) return std::nullopt;
  std::vector<uint8_t> out(4 + payload.size());
  write_u32_be(static_cast<uint32_t>(payload.size()), out.data());
  std::memcpy(out.data() + 4, payload.data(), payload.size());
  return out;
}

inline std::optional<json> parse_framed_json_bytes(std::span<const uint8_t> bytes,
                                                   std::size_t max_len = kMaxFrameSize) {
  if (bytes.size() < 4) return std::nullopt;
  const uint32_t len = read_u32_be(bytes.data());
  if (len == 0 || len > max_len) return std::nullopt;
  if (bytes.size() != 4 + len) return std::nullopt;
  try {
    const std::string s(reinterpret_cast<const char*>(bytes.data() + 4), len);
    return json::parse(s);
  } catch (...) {
    return std::nullopt;
  }
}

template <class AsyncReadStream, class Handler>
inline void async_read_frame(AsyncReadStream& stream,
                             std::shared_ptr<std::array<uint8_t, 4>> header_buf,
                             std::shared_ptr<std::vector<uint8_t>> body_buf,
                             std::size_t max_len,
                             Handler&& handler) {
  boost::asio::async_read(
      stream,
      boost::asio::buffer(*header_buf),
      [&, header_buf, body_buf, max_len, handler = std::forward<Handler>(handler)](
          const boost::system::error_code& ec, std::size_t) mutable {
        if (ec) return handler(ec, std::vector<uint8_t>{});
        const uint32_t len = read_u32_be(header_buf->data());
        if (len == 0 || len > max_len) {
          return handler(boost::asio::error::message_size, std::vector<uint8_t>{});
        }
        body_buf->assign(len, 0);
        boost::asio::async_read(
            stream,
            boost::asio::buffer(*body_buf),
            [body_buf, handler = std::move(handler)](const boost::system::error_code& ec2,
                                                     std::size_t) mutable {
              if (ec2) return handler(ec2, std::vector<uint8_t>{});
              return handler(ec2, *body_buf);
            });
      });
}

template <class AsyncReadStream, class Handler>
inline void async_read_frame(AsyncReadStream& stream, std::size_t max_len, Handler&& handler) {
  async_read_frame(stream,
                   std::make_shared<std::array<uint8_t, 4>>(),
                   std::make_shared<std::vector<uint8_t>>(),
                   max_len,
                   std::forward<Handler>(handler));
}

template <class AsyncReadStream, class Handler>
inline void async_read_json(AsyncReadStream& stream, std::size_t max_len, Handler&& handler) {
  async_read_frame(stream, max_len, [handler = std::forward<Handler>(handler)](
                                        const boost::system::error_code& ec,
                                        std::vector<uint8_t> body) mutable {
    if (ec) return handler(ec, json{});
    try {
      const std::string s(reinterpret_cast<const char*>(body.data()), body.size());
      json j = json::parse(s);
      handler(ec, std::move(j));
    } catch (...) {
      handler(boost::asio::error::invalid_argument, json{});
    }
  });
}

template <class AsyncWriteStream, class Handler>
inline void async_write_frame(AsyncWriteStream& stream,
                              std::shared_ptr<std::string> payload,
                              Handler&& handler) {
  auto buf = std::make_shared<std::vector<uint8_t>>();
  buf->resize(4 + payload->size());
  write_u32_be(static_cast<uint32_t>(payload->size()), buf->data());
  std::memcpy(buf->data() + 4, payload->data(), payload->size());

  boost::asio::async_write(
      stream,
      boost::asio::buffer(*buf),
      [buf, payload, handler = std::forward<Handler>(handler)](const boost::system::error_code& ec,
                                                              std::size_t) mutable {
        handler(ec);
      });
}

template <class AsyncWriteStream, class Handler>
inline void async_write_json(AsyncWriteStream& stream, const json& j, Handler&& handler) {
  auto payload = std::make_shared<std::string>(j.dump());
  if (payload->size() == 0 || payload->size() > kMaxFrameSize) {
    boost::asio::post(stream.get_executor(),
                      [handler = std::forward<Handler>(handler)]() mutable {
                        handler(boost::asio::error::message_size);
                      });
    return;
  }
  async_write_frame(stream, std::move(payload), std::forward<Handler>(handler));
}

// A tiny write-queue helper for framed JSON messages.
template <class AsyncWriteStream>
class JsonWriteQueue : public std::enable_shared_from_this<JsonWriteQueue<AsyncWriteStream>> {
 public:
  explicit JsonWriteQueue(AsyncWriteStream& stream) : stream_(stream) {}

  void send(json msg) {
    pending_.push_back(std::move(msg));
    if (writing_) return;
    writing_ = true;
    do_write();
  }

 private:
  void do_write() {
    if (pending_.empty()) {
      writing_ = false;
      return;
    }
    auto self = this->shared_from_this();
    json msg = std::move(pending_.front());
    pending_.pop_front();
    async_write_json(stream_, msg, [self](const boost::system::error_code&) { self->do_write(); });
  }

  AsyncWriteStream& stream_;
  std::deque<json> pending_;
  bool writing_ = false;
};

} // namespace common
