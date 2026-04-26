// Router implementation — forward table for incoming PEER_HANDSHAKE
// and PEER_HOLEPUNCH. Maps target hash → ForwardEntry (the Server
// instance that listens at that key).
//
// JS: .analysis/js/hyperdht/lib/router.js:20-249 (whole Router class)
//
// C++ diffs from JS:
//   - JS uses xache `Cache` with TTL-based eviction. C++ uses a plain
//     std::unordered_map keyed by 32-byte target.
//   - JS Router both forwards AND originates client requests
//     (peerHandshake / peerHolepunch). C++ only handles the server side
//     (forwarding); client side lives in src/peer_connect.cpp.
//   - FROM_SECOND_RELAY is partially handled — we send back to req.from,
//     not the embedded relayAddress (see TODO in handle_peer_handshake).

#include "hyperdht/router.hpp"

#include <cstring>

#include "hyperdht/debug.hpp"
#include "hyperdht/holepunch.hpp"

namespace hyperdht {
namespace router {

void Router::set(const announce::TargetKey& target, ForwardEntry entry) {
    forwards_[target] = std::move(entry);
}

ForwardEntry* Router::get(const announce::TargetKey& target) {
    auto it = forwards_.find(target);
    if (it == forwards_.end()) return nullptr;
    return &it->second;
}

void Router::remove(const announce::TargetKey& target) {
    forwards_.erase(target);
}

bool Router::has(const announce::TargetKey& target) const {
    return forwards_.count(target) > 0;
}

const std::vector<uint8_t>* Router::record(const announce::TargetKey& target) const {
    auto it = forwards_.find(target);
    if (it == forwards_.end()) return nullptr;
    if (it->second.record.empty()) return nullptr;
    return &it->second.record;
}

void Router::clear() {
    forwards_.clear();
}

// ---------------------------------------------------------------------------
// Handle incoming PEER_HANDSHAKE
//
// JS: .analysis/js/hyperdht/lib/router.js:81-172 (onpeerhandshake)
//
// JS dispatches on `mode` (FROM_CLIENT/FROM_RELAY/FROM_SECOND_RELAY):
//   - FROM_CLIENT: req.reply with REPLY mode
//   - FROM_RELAY:  req.relay back with FROM_SERVER mode
//   - FROM_SECOND_RELAY: req.relay to embedded relayAddress
// C++ accepts all three but treats FROM_RELAY and FROM_SECOND_RELAY
// identically (sends back to req.from with mode FROM_SERVER).
// ---------------------------------------------------------------------------

bool Router::handle_peer_handshake(const messages::Request& req,
                                   ReplyFn reply, RelayFn relay) {
    if (!req.target.has_value() || !req.value.has_value()) {
        DHT_LOG( "  [router] HS: missing target=%d value=%d\n",
                req.target.has_value() ? 1 : 0, req.value.has_value() ? 1 : 0);
        return false;
    }

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    auto* entry = get(target);
    if (!entry) {
        DHT_LOG( "  [router] HS: target %02x%02x... not in router (size=%zu)\n",
                target[0], target[1], forwards_.size());
        return false;
    }

    // Decode the handshake message to extract noise bytes + peerAddress
    auto hs_msg = peer_connect::decode_handshake_msg(
        req.value->data(), req.value->size());
    if (hs_msg.noise.empty()) return false;
    if (hs_msg.mode != peer_connect::MODE_FROM_CLIENT &&
        hs_msg.mode != peer_connect::MODE_FROM_RELAY &&
        hs_msg.mode != peer_connect::MODE_FROM_SECOND_RELAY &&
        hs_msg.mode != peer_connect::MODE_FROM_SERVER) return false;

    // ----- Relay-only entry path -----
    // JS parity: lib/router.js:128-170 (the `else` branch when state has
    // no `onpeerhandshake`, only `relay`). We act as a forwarder one hop
    // closer to the actual server.
    if (!entry->on_peer_handshake) {
        if (!entry->relay.has_value()) return false;
        const auto relay_addr = *entry->relay;

        switch (hs_msg.mode) {
            case peer_connect::MODE_FROM_CLIENT: {
                // Forward FROM_CLIENT → FROM_RELAY toward the server,
                // stashing the original client's wire address so the
                // server's reply can be routed back through us.
                peer_connect::HandshakeMessage fwd;
                fwd.mode = peer_connect::MODE_FROM_RELAY;
                fwd.noise = hs_msg.noise;
                fwd.peer_address = req.from.addr;

                messages::Request fwd_req;
                fwd_req.tid = req.tid;
                fwd_req.to.addr = relay_addr;
                fwd_req.command = req.command;
                fwd_req.target = req.target;
                fwd_req.internal = false;
                fwd_req.value = peer_connect::encode_handshake_msg(fwd);
                relay(fwd_req);
                return true;
            }
            case peer_connect::MODE_FROM_SERVER: {
                // Server's reply coming back through us — convert to
                // REPLY mode for the original client whose address is
                // carried in `peerAddress`.
                if (!hs_msg.peer_address.has_value()) return false;
                peer_connect::HandshakeMessage rep;
                rep.mode = peer_connect::MODE_REPLY;
                rep.noise = hs_msg.noise;
                rep.peer_address = req.from.addr;

                messages::Response resp;
                resp.tid = req.tid;
                resp.from.addr = *hs_msg.peer_address;  // routed-to client
                resp.value = peer_connect::encode_handshake_msg(rep);
                reply(resp);
                return true;
            }
            default:
                // FROM_RELAY / FROM_SECOND_RELAY at a relay node would
                // require a second forwarding hop. Unsupported for now;
                // see `relay/peer_connect/holepunch` follow-up TODO.
                return false;
        }
    }

    DHT_LOG( "  [router] HS: target FOUND, noise=%zu bytes, mode=%u\n",
            hs_msg.noise.size(), hs_msg.mode);

    // The client's address (FROM_RELAY: from the peerAddress field; FROM_CLIENT: from the packet)
    auto client_addr = hs_msg.peer_address.value_or(req.from.addr);
    auto incoming_mode = hs_msg.mode;

    // Capture only the fields we need (avoid copying the full Request with its value vector)
    auto req_tid = req.tid;
    auto req_from = req.from.addr;
    auto req_command = req.command;
    auto req_target = req.target;

    // Call the server's handler. It will call reply_fn with the Noise msg2.
    entry->on_peer_handshake(
        hs_msg.noise, client_addr,
        [req_tid, req_from, req_command, req_target,
         reply, relay, client_addr, incoming_mode](std::vector<uint8_t> reply_noise) {
            DHT_LOG( "  [router] reply_fn called, noise=%zu bytes, incoming_mode=%u\n",
                    reply_noise.size(), incoming_mode);

            if (incoming_mode == peer_connect::MODE_FROM_CLIENT) {
                // Direct connection: send RESPONSE with mode=REPLY to the client
                peer_connect::HandshakeMessage resp_msg;
                resp_msg.mode = peer_connect::MODE_REPLY;
                resp_msg.noise = std::move(reply_noise);

                messages::Response resp;
                resp.tid = req_tid;
                resp.from.addr = req_from;
                resp.value = peer_connect::encode_handshake_msg(resp_msg);

                reply(resp);
            } else {
                // FROM_RELAY (or FROM_SECOND_RELAY — see note below): send REQUEST
                // back to relay with mode=FROM_SERVER. The relay node converts this
                // to a RESPONSE for the original client. TID is preserved.
                //
                // NOTE: FROM_SECOND_RELAY should send to relayAddress (the first
                // relay), not req.from (the second relay). This is not yet
                // implemented — second-relay is a rare edge case that requires the
                // client to specify a relayAddress.
                peer_connect::HandshakeMessage relay_msg;
                relay_msg.mode = peer_connect::MODE_FROM_SERVER;
                relay_msg.noise = std::move(reply_noise);
                relay_msg.peer_address = client_addr;

                messages::Request relay_req;
                relay_req.tid = req_tid;
                relay_req.to.addr = req_from;       // Back to relay node
                relay_req.command = req_command;
                relay_req.target = req_target;
                relay_req.internal = false;
                relay_req.value = peer_connect::encode_handshake_msg(relay_msg);

                relay(relay_req);
            }
        });

    return true;
}

// ---------------------------------------------------------------------------
// Handle incoming PEER_HOLEPUNCH
//
// JS: .analysis/js/hyperdht/lib/router.js:202-248 (onpeerholepunch)
//
// JS dispatches on `mode`:
//   - FROM_CLIENT: relay to peerAddress or known forward target
//   - FROM_RELAY:  call state.onpeerholepunch then relay back FROM_SERVER
//   - FROM_SERVER: req.reply with REPLY mode + the embedded peerAddress
// C++ handles only the server-side path (the relay-only forward case is
// not yet implemented — incoming non-FROM_CLIENT messages are processed
// by the local Server entry directly).
// ---------------------------------------------------------------------------

bool Router::handle_peer_holepunch(const messages::Request& req,
                                   ReplyFn reply, RelayFn relay) {
    if (!req.target.has_value() || !req.value.has_value()) return false;

    announce::TargetKey target{};
    std::copy(req.target->begin(), req.target->end(), target.begin());

    auto* entry = get(target);
    if (!entry) return false;

    // Decode the holepunch message to determine the mode
    auto hp_msg = holepunch::decode_holepunch_msg(req.value->data(), req.value->size());
    auto incoming_mode = hp_msg.mode;
    auto client_addr = hp_msg.peer_address.value_or(req.from.addr);

    // ----- Relay-only entry path (announceSelf forwards) -----
    // JS parity: lib/router.js:212-247 — relay-only nodes forward
    // FROM_CLIENT messages to the announcer/server and convert
    // FROM_SERVER messages back into REPLYs for the original client.
    if (!entry->on_peer_holepunch) {
        if (!entry->relay.has_value()) return false;
        const auto relay_addr = *entry->relay;

        switch (incoming_mode) {
            case peer_connect::MODE_FROM_CLIENT: {
                holepunch::HolepunchMessage fwd = hp_msg;
                fwd.mode = peer_connect::MODE_FROM_RELAY;
                fwd.peer_address = req.from.addr;

                messages::Request fwd_req;
                fwd_req.tid = req.tid;
                fwd_req.to.addr = relay_addr;
                fwd_req.command = req.command;
                fwd_req.target = req.target;
                fwd_req.internal = false;
                fwd_req.value = holepunch::encode_holepunch_msg(fwd);
                relay(fwd_req);
                return true;
            }
            case peer_connect::MODE_FROM_SERVER: {
                if (!hp_msg.peer_address.has_value()) return false;
                holepunch::HolepunchMessage rep = hp_msg;
                rep.mode = peer_connect::MODE_REPLY;
                rep.peer_address = req.from.addr;

                messages::Response resp;
                resp.tid = req.tid;
                resp.from.addr = *hp_msg.peer_address;
                resp.value = holepunch::encode_holepunch_msg(rep);
                reply(resp);
                return true;
            }
            default:
                return false;
        }
    }

    // Capture only needed fields (avoid copying the full Request)
    auto req_tid = req.tid;
    auto req_from = req.from.addr;
    auto req_command = req.command;
    auto req_target = req.target;

    // Pass the raw value and client address to the server's handler.
    // The handler decrypts/processes and calls reply_fn with the reply value.
    // NOTE: The callback returns a fully-encoded HolepunchMessage. The router
    // decodes it to overwrite the mode field (FROM_SERVER or REPLY) and
    // peerAddress, then re-encodes. This is asymmetric with the handshake path
    // (which returns raw Noise bytes) but functionally correct.
    entry->on_peer_holepunch(
        *req.value, client_addr,
        [req_tid, req_from, req_command, req_target,
         reply, relay, client_addr, incoming_mode](std::vector<uint8_t> reply_value) {
            if (incoming_mode == peer_connect::MODE_FROM_CLIENT) {
                // Direct: send RESPONSE to client with mode=REPLY
                auto hp_reply = holepunch::decode_holepunch_msg(
                    reply_value.data(), reply_value.size());
                hp_reply.mode = peer_connect::MODE_REPLY;
                hp_reply.peer_address = std::nullopt;

                messages::Response resp;
                resp.tid = req_tid;
                resp.from.addr = req_from;
                resp.value = holepunch::encode_holepunch_msg(hp_reply);
                reply(resp);
            } else {
                // FROM_RELAY: send REQUEST back to relay with mode=FROM_SERVER
                auto hp_relay = holepunch::decode_holepunch_msg(
                    reply_value.data(), reply_value.size());
                hp_relay.mode = peer_connect::MODE_FROM_SERVER;
                hp_relay.peer_address = client_addr;

                messages::Request relay_req;
                relay_req.tid = req_tid;
                relay_req.to.addr = req_from;
                relay_req.command = req_command;
                relay_req.target = req_target;
                relay_req.internal = false;
                relay_req.value = holepunch::encode_holepunch_msg(hp_relay);

                relay(relay_req);
            }
        });

    return true;
}

}  // namespace router
}  // namespace hyperdht
