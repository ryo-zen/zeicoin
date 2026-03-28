const multiaddr = @import("multiaddr/multiaddr.zig");
const tcp = @import("transport/tcp.zig");
const multistream = @import("protocol/multistream.zig");
const identify_proto = @import("protocol/identify.zig");
const peer_id = @import("peer/peer_id.zig");
const noise_proto = @import("security/noise.zig");
const yamux_proto = @import("muxer/yamux.zig");
const handler_registry_mod = @import("host/handler_registry.zig");

pub const Multiaddr = multiaddr.Multiaddr;
pub const TcpTransport = tcp.TcpTransport;
pub const TcpConnection = tcp.TcpConnection;
pub const ms = multistream;
pub const identify = identify_proto;
pub const PeerId = peer_id.PeerId;
pub const IdentityKey = peer_id.IdentityKey;
pub const noise = noise_proto;
pub const yamux = yamux_proto;
pub const HandlerRegistry = handler_registry_mod.HandlerRegistry;
pub const Handler = handler_registry_mod.Handler;

const inproc_mod = @import("transport/inproc.zig");
pub const InProcConnection = inproc_mod.InProcConnection;

const host_mod = @import("host/host.zig");
pub const Host = host_mod.Host;
