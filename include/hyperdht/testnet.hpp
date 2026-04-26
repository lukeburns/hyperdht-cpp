#pragma once

// Testnet — port of `hyperdht/testnet.js` for unit/live tests.
//
// Spawns N persistent, non-firewalled HyperDHT nodes bound to 127.0.0.1
// with kernel-assigned ports. The first node has no upstream bootstrap;
// subsequent nodes use the first's address as their bootstrap. Drives
// `uv_run(loop, UV_RUN_NOWAIT)` until every node has finished its
// bootstrap walk (or `timeout_ms` elapses).
//
// Usage:
//   uv_loop_t loop;
//   uv_loop_init(&loop);
//   auto net = hyperdht::testnet::Testnet::create(&loop, 3);
//   ASSERT_NE(net, nullptr);
//   // net->node(0..2) are now ready for use.
//   net->destroy();
//   uv_run(&loop, UV_RUN_DEFAULT);
//   uv_loop_close(&loop);
//
// JS reference: hyperdht/testnet.js (lines 3-44 — createTestnet).
//
// Implementation note — the localhost testnet relies on
// `HyperDHT::force_persistent()` (see `hyperdht/dht.hpp`) to pin every
// member to its bound (127.0.0.1, port) address up front. Without that
// shortcut the routing-table validation chicken-and-egg keeps every
// table empty: nodes start with random ids that fail `compute_peer_id`
// validation at the receiver, the NAT sampler in our port needs ≥3
// distinct samples to converge, and the very first member has no
// upstream traffic to seed the sampler. JS dodges this through
// `DHT.bootstrapper`'s `_nat.add(host, port)` pre-seed combined with
// the JS NatSampler's single-sample classification — both differ from
// our implementation. `force_persistent()` collapses the same outcome
// into one synchronous call, deterministic and parity-preserving.

#include <cstdint>
#include <memory>
#include <vector>

#include <uv.h>

#include "hyperdht/compact.hpp"
#include "hyperdht/dht.hpp"

namespace hyperdht {
namespace testnet {

class Testnet {
public:
    // Spawn `n` testnet members. Returns nullptr if the first node fails
    // to bind, or if the bootstrap timeout fires before every member is
    // ready.
    //
    // Bring-up dance (mirrors what JS gets for free via the dual-socket
    // `serverSocket`/`clientSocket` split + single-sample NatSampler):
    //   1. Bind each member, then immediately `force_persistent` on the
    //      bound (127.0.0.1, port) address. This pins the
    //      routing-table id BEFORE the loop pumps the first bootstrap
    //      packet, which means every response carries the right id and
    //      passes recipient-side `compute_peer_id` validation.
    //   2. Pump the loop until each member's initial bootstrap walk
    //      completes (`on_bootstrapped`). At this point persistent
    //      members all know the bootstrapper but the bootstrapper has
    //      an empty table, because the first walk's outbound requests
    //      were already in flight when `force_persistent` ran (request
    //      encoding captures `ephemeral_/firewalled_` synchronously
    //      inside `RpcSocket::request`).
    //   3. Run a `refresh()` on every member. The refresh fires
    //      requests after the persistent flip, so the requests now
    //      carry the address-based id and the bootstrapper finally
    //      gets to add everyone to its own table. Settle for 200ms.
    static std::unique_ptr<Testnet> create(uv_loop_t* loop, size_t n,
                                           uint64_t timeout_ms = 10000) {
        if (n == 0 || loop == nullptr) return nullptr;

        std::unique_ptr<Testnet> net(new Testnet(loop));

        // First node: no upstream bootstrap, persistent, non-firewalled.
        DhtOptions first_opts;
        first_opts.host = "127.0.0.1";
        first_opts.port = 0;
        first_opts.ephemeral = false;
        first_opts.bootstrap.clear();

        auto first = std::make_unique<HyperDHT>(loop, first_opts);
        if (first->bind() != 0) return nullptr;
        first->set_firewalled(false);

        const uint16_t first_port = first->port();
        first->force_persistent(
            compact::Ipv4Address::from_string("127.0.0.1", first_port));

        net->bootstrap_.push_back(
            compact::Ipv4Address::from_string("127.0.0.1", first_port));
        net->nodes_.push_back(std::move(first));

        // Remaining nodes: bootstrap off the first.
        std::vector<bool> ready(n, false);
        ready[0] = true;
        size_t pending = n - 1;

        for (size_t i = 1; i < n; ++i) {
            DhtOptions opts;
            opts.host = "127.0.0.1";
            opts.port = 0;
            opts.ephemeral = false;
            opts.bootstrap = net->bootstrap_;

            auto node = std::make_unique<HyperDHT>(loop, opts);

            // Install the readiness callback BEFORE bind so we don't
            // miss the synchronous fire path.
            const size_t idx = i;
            node->on_bootstrapped(
                [&ready, &pending, idx]() {
                    if (!ready[idx]) {
                        ready[idx] = true;
                        if (pending > 0) --pending;
                    }
                });

            if (node->bind() != 0) return nullptr;
            node->set_firewalled(false);
            // Pin synchronously after bind, before the loop pumps the
            // bootstrap walk. See file-level note for why this is
            // required to avoid empty routing tables on localhost.
            node->force_persistent(compact::Ipv4Address::from_string(
                "127.0.0.1", node->port()));
            net->nodes_.push_back(std::move(node));
        }

        // Phase 1: drive the loop until every member has finished its
        // initial bootstrap walk (or the deadline trips).
        const uint64_t deadline = uv_now(loop) + timeout_ms;
        while (pending > 0 && uv_now(loop) < deadline) {
            uv_run(loop, UV_RUN_NOWAIT);
        }
        if (pending > 0) return nullptr;

        // Phase 2: kick a refresh on every member so the bootstrapper
        // (and any other peers that didn't see id-bearing requests in
        // phase 1) get added to each other's routing tables. This is
        // analogous to the second `_backgroundQuery` iteration in JS
        // `_bootstrap`, which runs after the id rebuild.
        for (auto& n_ptr : net->nodes_) {
            n_ptr->refresh();
        }

        // Phase 3: settle for 200ms. RPC round-trips are sub-millisecond
        // on localhost, but allow a generous margin for the refresh
        // queries to land before returning. Bounded by `timeout_ms`.
        const uint64_t settle_deadline =
            std::min(uv_now(loop) + 200, deadline);
        while (uv_now(loop) < settle_deadline) {
            uv_run(loop, UV_RUN_NOWAIT);
        }

        return net;
    }

    ~Testnet() { destroy(); }

    Testnet(const Testnet&) = delete;
    Testnet& operator=(const Testnet&) = delete;

    HyperDHT* node(size_t i) const {
        return i < nodes_.size() ? nodes_[i].get() : nullptr;
    }
    size_t size() const { return nodes_.size(); }
    const std::vector<compact::Ipv4Address>& bootstrap() const {
        return bootstrap_;
    }
    uv_loop_t* loop() const { return loop_; }

    // Spawn an additional ephemeral node into the existing testnet. The
    // returned pointer is owned by this Testnet. Returns nullptr on
    // bind failure or if `timeout_ms` elapses before bootstrap.
    HyperDHT* add_ephemeral_node(uint64_t timeout_ms = 5000) {
        DhtOptions opts;
        opts.host = "127.0.0.1";
        opts.port = 0;
        opts.ephemeral = true;
        opts.bootstrap = bootstrap_;

        auto node = std::make_unique<HyperDHT>(loop_, opts);

        bool ready = false;
        node->on_bootstrapped([&ready]() { ready = true; });
        if (node->bind() != 0) return nullptr;

        const uint64_t deadline = uv_now(loop_) + timeout_ms;
        while (!ready && uv_now(loop_) < deadline) {
            uv_run(loop_, UV_RUN_NOWAIT);
        }
        if (!ready) return nullptr;

        HyperDHT* raw = node.get();
        nodes_.push_back(std::move(node));
        return raw;
    }

    // Destroy every node and drain the loop. Idempotent.
    void destroy() {
        if (destroyed_) return;
        destroyed_ = true;

        // Tear down in reverse order — JS testnet.js:71-73 destroys
        // nodes from the most-recently-added back to the bootstrap.
        size_t pending = nodes_.size();
        for (auto it = nodes_.rbegin(); it != nodes_.rend(); ++it) {
            (*it)->destroy([&pending]() {
                if (pending > 0) --pending;
            });
        }

        // Drain — bounded so a stuck node can't hang the test process.
        const uint64_t deadline = uv_now(loop_) + 5000;
        while (pending > 0 && uv_now(loop_) < deadline) {
            uv_run(loop_, UV_RUN_NOWAIT);
        }

        nodes_.clear();
        bootstrap_.clear();
    }

private:
    explicit Testnet(uv_loop_t* loop) : loop_(loop) {}

    uv_loop_t* loop_;
    std::vector<std::unique_ptr<HyperDHT>> nodes_;
    std::vector<compact::Ipv4Address> bootstrap_;
    bool destroyed_ = false;
};

}  // namespace testnet
}  // namespace hyperdht
