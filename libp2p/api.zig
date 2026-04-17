// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: MIT

const multiaddr = @import("multiaddr/multiaddr.zig");
const tcp = @import("transport/tcp.zig");
const multistream = @import("protocol/multistream.zig");
const identify_proto = @import("protocol/identify.zig");
const peer_id = @import("peer/peer_id.zig");
const address_book_module = @import("peer/address_book.zig");
const noise_proto = @import("security/noise.zig");
const yamux_proto = @import("muxer/yamux.zig");
const handler_registry_mod = @import("host/handler_registry.zig");
const kad_mod = @import("dht/message.zig");
const kad_query_mod = @import("dht/query.zig");
const kad_routing_mod = @import("dht/routing_table.zig");
const kad_store_mod = @import("dht/store.zig");

pub const Multiaddr = multiaddr.Multiaddr;
pub const TcpTransport = tcp.TcpTransport;
pub const TcpConnection = tcp.TcpConnection;
pub const ms = multistream;
pub const identify = identify_proto;
pub const PeerId = peer_id.PeerId;
pub const IdentityKey = peer_id.IdentityKey;
pub const AddressBook = address_book_module.AddressBook;
pub const address_book = address_book_module;
pub const noise = noise_proto;
pub const yamux = yamux_proto;
pub const kad = kad_mod;
pub const kad_query = kad_query_mod;
pub const kad_routing = kad_routing_mod;
pub const kad_store = kad_store_mod;
pub const HandlerRegistry = handler_registry_mod.HandlerRegistry;
pub const Handler = handler_registry_mod.Handler;
pub const ConnInfo = handler_registry_mod.ConnInfo;

const inproc_mod = @import("transport/inproc.zig");
pub const InProcConnection = inproc_mod.InProcConnection;

const host_mod = @import("host/host.zig");
pub const Host = host_mod.Host;
