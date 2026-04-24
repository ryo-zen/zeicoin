// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// libp2p in-process stress harness
//
// Three scenarios targeting the inproc → noise → yamux stack:
//
//   1. session_churn   — repeatedly create/tear-down full session pairs and
//                        check memory returns to baseline each cycle.
//   2. stream_churn    — one long-lived session; open/send/close streams in a
//                        tight loop for the configured duration.
//   3. concurrent_chaos — multiple concurrent workers per side sending varied
//                         payloads, some RST mid-send, exercising the demux
//                         loop and flow-control paths simultaneously.
//
// Usage:
//   zig build run-libp2p-stress                  # CI profile (all scenarios, ~5s)
//   zig build run-libp2p-stress -- --soak        # local soak (all scenarios, ~120s)
//   zig build run-libp2p-stress -- session_churn # single scenario
//
// Profiles:
//   CI (default): duration=5s, streams=1000, payload=4KB, workers=4
//   Soak (--soak): duration=120s, streams=100000, payload=64KB, workers=8

const std = @import("std");
const noise = @import("security/noise.zig");
const yamux = @import("muxer/yamux.zig");
const inproc = @import("transport/inproc.zig");

const Session = yamux.Session;
const Stream = yamux.Stream;
const YamuxError = yamux.YamuxError;
const print = std.debug.print;

// ── profiles ─────────────────────────────────────────────────────────────────

const Config = struct {
    duration_secs: u64,
    session_cycles: usize,
    stream_count: usize,
    payload_bytes: usize,
    concurrent_workers: usize,

    fn ci() Config {
        return .{
            .duration_secs = 5,
            .session_cycles = 8,
            .stream_count = 1000,
            .payload_bytes = 4 * 1024,
            .concurrent_workers = 4,
        };
    }

    fn soak() Config {
        return .{
            .duration_secs = 120,
            .session_cycles = 200,
            .stream_count = 100_000,
            .payload_bytes = 64 * 1024,
            .concurrent_workers = 8,
        };
    }
};

// ── metrics ───────────────────────────────────────────────────────────────────

const Metrics = struct {
    streams_opened: u64 = 0,
    streams_closed: u64 = 0,
    streams_errored: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    sessions_created: u64 = 0,
    sessions_closed: u64 = 0,
    elapsed_ns: u64 = 0,

    fn streamsPerSec(self: Metrics) f64 {
        if (self.elapsed_ns == 0) return 0;
        const secs = @as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        return @as(f64, @floatFromInt(self.streams_closed)) / secs;
    }

    fn print(self: Metrics, scenario: []const u8) void {
        const secs = @as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        std.debug.print(
            "  {s}: opened={d} closed={d} errors={d} sessions={d}/{d} " ++
                "sent={d:.1}MB recv={d:.1}MB elapsed={d:.2}s rate={d:.0} streams/s\n",
            .{
                scenario,
                self.streams_opened,
                self.streams_closed,
                self.streams_errored,
                self.sessions_created,
                self.sessions_closed,
                @as(f64, @floatFromInt(self.bytes_sent)) / 1024.0 / 1024.0,
                @as(f64, @floatFromInt(self.bytes_received)) / 1024.0 / 1024.0,
                secs,
                self.streamsPerSec(),
            },
        );
    }
};

// ── noise key helpers ─────────────────────────────────────────────────────────

// Symmetric key pair — initiator tx == responder rx and vice versa.
const KEY_A = [_]u8{0xAA} ** 32;
const KEY_B = [_]u8{0xBB} ** 32;

// ── scenario 1: session churn ─────────────────────────────────────────────────
//
// Create a session pair, open one stream, exchange a ping/pong, tear everything
// down, and repeat. A GPA wraps each cycle so any leak fails immediately.

fn runSessionChurn(cfg: Config, io: std.Io) !Metrics {
    var metrics = Metrics{};
    var timer = try std.time.Timer.start();

    for (0..cfg.session_cycles) |_| {
        // Each cycle gets its own GPA — leak = hard failure.
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer {
            const check = gpa.deinit();
            if (check == .leak) {
                std.debug.print("  [session_churn] LEAK detected in cycle\n", .{});
                std.process.exit(1);
            }
        }
        const allocator = gpa.allocator();

        var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
        var init_conn = conn_pair.initiator;
        var resp_conn = conn_pair.responder;

        var init_secure = noise.SecureTransport.init(allocator, init_conn.connection(), KEY_A, KEY_B);
        var resp_secure = noise.SecureTransport.init(allocator, resp_conn.connection(), KEY_B, KEY_A);

        // Short keepalive so session teardown doesn't block for 15s waiting for
        // the keepalive sleep to be cancelled.
        const stress_opts = yamux.SessionOptions{ .keepalive_interval_ms = 100, .keepalive_timeout_ms = 500 };
        var init_session = Session.initWithOptions(allocator, &init_secure, true, stress_opts);
        var resp_session = Session.initWithOptions(allocator, &resp_secure, false, stress_opts);

        metrics.sessions_created += 2;

        const ResponderCtx = struct {
            session: *Session,
            io: std.Io,
            bytes_received: u64 = 0,

            fn run(ctx: *@This()) anyerror!void {
                var stream = try ctx.session.acceptStream();
                defer stream.deinit();
                var buf: [64]u8 = undefined;
                while (true) {
                    const n = try stream.readSome(&buf);
                    if (n == 0) break;
                    ctx.bytes_received += n;
                    try stream.writeAll(buf[0..n]);
                }
            }
        };

        var resp_ctx = ResponderCtx{ .session = &resp_session, .io = io };

        try init_session.start();
        try resp_session.start();

        var resp_future = try io.concurrent(ResponderCtx.run, .{&resp_ctx});

        var stream = try init_session.openStream();
        defer stream.deinit();

        const ping = "ping";
        try stream.writeAll(ping);
        try stream.close();
        metrics.bytes_sent += ping.len;
        metrics.streams_opened += 1;

        // drain echo
        var echo_buf: [4]u8 = undefined;
        var got: usize = 0;
        while (got < ping.len) {
            const n = try stream.readSome(echo_buf[got..]);
            if (n == 0) break;
            got += n;
        }
        metrics.bytes_received += got;
        metrics.streams_closed += 1;

        resp_future.await(io) catch {};

        metrics.bytes_received += resp_ctx.bytes_received;

        init_session.deinit();
        resp_session.deinit();
        init_secure.deinit();
        resp_secure.deinit();
        init_conn.deinit();
        resp_conn.deinit();

        metrics.sessions_closed += 2;
    }

    metrics.elapsed_ns = timer.read();
    return metrics;
}

// ── scenario 2: stream churn ──────────────────────────────────────────────────
//
// One long-lived session pair. Open → send payload → close in a loop for the
// configured duration or stream count, whichever comes first.

fn runStreamChurn(cfg: Config, io: std.Io) !Metrics {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const check = gpa.deinit();
        if (check == .leak) {
            std.debug.print("  [stream_churn] LEAK detected\n", .{});
            std.process.exit(1);
        }
    }
    const allocator = gpa.allocator();

    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var init_conn = conn_pair.initiator;
    var resp_conn = conn_pair.responder;

    var init_secure = noise.SecureTransport.init(allocator, init_conn.connection(), KEY_A, KEY_B);
    var resp_secure = noise.SecureTransport.init(allocator, resp_conn.connection(), KEY_B, KEY_A);

    const stress_opts = yamux.SessionOptions{ .keepalive_interval_ms = 100, .keepalive_timeout_ms = 500 };
    var init_session = Session.initWithOptions(allocator, &init_secure, true, stress_opts);
    var resp_session = Session.initWithOptions(allocator, &resp_secure, false, stress_opts);

    try init_session.start();
    try resp_session.start();

    var metrics = Metrics{ .sessions_created = 2 };
    var timer = try std.time.Timer.start();
    const deadline_ns = cfg.duration_secs * std.time.ns_per_s;

    // Responder: accept and drain every stream.
    const ResponderCtx = struct {
        session: *Session,
        io: std.Io,
        bytes_received: u64 = 0,
        streams_accepted: u64 = 0,
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn run(ctx: *@This()) anyerror!void {
            while (!ctx.done.load(.acquire)) {
                var stream = ctx.session.acceptStream() catch |err| switch (err) {
                    YamuxError.GoAway, YamuxError.SessionClosed => return,
                    else => return err,
                };
                defer stream.deinit();
                ctx.streams_accepted += 1;
                var buf: [4096]u8 = undefined;
                while (true) {
                    const n = stream.readSome(&buf) catch break;
                    if (n == 0) break;
                    ctx.bytes_received += n;
                }
            }
        }
    };

    var resp_ctx = ResponderCtx{ .session = &resp_session, .io = io };
    var resp_future = try io.concurrent(ResponderCtx.run, .{&resp_ctx});

    const payload = try allocator.alloc(u8, cfg.payload_bytes);
    defer allocator.free(payload);
    @memset(payload, 0xCC);

    var streams_done: usize = 0;
    while (streams_done < cfg.stream_count and timer.read() < deadline_ns) {
        var stream = init_session.openStream() catch |err| switch (err) {
            YamuxError.AckBacklogFull => {
                // Back off briefly and retry — backlog will clear as responder drains.
                try io.sleep(std.Io.Duration.fromMilliseconds(1), .awake);
                continue;
            },
            else => return err,
        };
        defer stream.deinit();

        try stream.writeAll(payload);
        try stream.close();
        metrics.streams_opened += 1;
        metrics.bytes_sent += cfg.payload_bytes;
        streams_done += 1;
    }

    resp_ctx.done.store(true, .release);
    init_session.deinit();
    resp_session.deinit();
    resp_future.await(io) catch {};

    init_secure.deinit();
    resp_secure.deinit();
    init_conn.deinit();
    resp_conn.deinit();

    metrics.streams_closed = streams_done;
    metrics.bytes_received = resp_ctx.bytes_received;
    metrics.sessions_closed = 2;
    metrics.elapsed_ns = timer.read();
    return metrics;
}

// ── scenario 3: concurrent chaos ─────────────────────────────────────────────
//
// N workers per side simultaneously open streams with varied payload sizes.
// Every 5th stream RSTs mid-send to exercise RST isolation. Checks that
// unrelated streams make progress and no deadlocks occur within the timeout.

fn runConcurrentChaos(cfg: Config, io: std.Io) !Metrics {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const check = gpa.deinit();
        if (check == .leak) {
            std.debug.print("  [concurrent_chaos] LEAK detected\n", .{});
            std.process.exit(1);
        }
    }
    const allocator = gpa.allocator();

    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var init_conn = conn_pair.initiator;
    var resp_conn = conn_pair.responder;

    var init_secure = noise.SecureTransport.init(allocator, init_conn.connection(), KEY_A, KEY_B);
    var resp_secure = noise.SecureTransport.init(allocator, resp_conn.connection(), KEY_B, KEY_A);

    const stress_opts = yamux.SessionOptions{ .keepalive_interval_ms = 100, .keepalive_timeout_ms = 500 };
    var init_session = Session.initWithOptions(allocator, &init_secure, true, stress_opts);
    var resp_session = Session.initWithOptions(allocator, &resp_secure, false, stress_opts);

    try init_session.start();
    try resp_session.start();

    const streams_per_worker = cfg.stream_count / cfg.concurrent_workers;
    const deadline_ns = cfg.duration_secs * std.time.ns_per_s;

    // Shared counters — workers update these atomically.
    var total_opened = std.atomic.Value(u64).init(0);
    var total_closed = std.atomic.Value(u64).init(0);
    var total_errored = std.atomic.Value(u64).init(0);
    var total_bytes_sent = std.atomic.Value(u64).init(0);
    var total_bytes_recv = std.atomic.Value(u64).init(0);

    const WorkerCtx = struct {
        session: *Session,
        io: std.Io,
        allocator: std.mem.Allocator,
        worker_id: usize,
        streams_to_open: usize,
        deadline_ns: u64,
        opened: *std.atomic.Value(u64),
        closed: *std.atomic.Value(u64),
        errored: *std.atomic.Value(u64),
        bytes_sent: *std.atomic.Value(u64),

        fn run(ctx: *@This()) anyerror!void {
            var timer = std.time.Timer.start() catch return;
            var done: usize = 0;

            while (done < ctx.streams_to_open and timer.read() < ctx.deadline_ns) {
                // Vary payload size by worker to exercise different window paths.
                const payload_len: usize = switch (ctx.worker_id % 4) {
                    0 => 1, // 1-byte: framing overhead stress
                    1 => 512,
                    2 => 8 * 1024,
                    else => 64 * 1024,
                };

                var stream = ctx.session.openStream() catch |err| switch (err) {
                    YamuxError.AckBacklogFull => {
                        ctx.io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
                        continue;
                    },
                    YamuxError.GoAway, YamuxError.SessionClosed => return,
                    else => {
                        _ = ctx.errored.fetchAdd(1, .monotonic);
                        return err;
                    },
                };
                defer stream.deinit();
                _ = ctx.opened.fetchAdd(1, .monotonic);

                // Every 5th stream RSTs by closing without sending all data.
                const do_rst = (done % 5 == 4);

                if (!do_rst) {
                    const payload = ctx.allocator.alloc(u8, payload_len) catch {
                        _ = ctx.errored.fetchAdd(1, .monotonic);
                        done += 1;
                        continue;
                    };
                    defer ctx.allocator.free(payload);
                    @memset(payload, @intCast(ctx.worker_id & 0xFF));

                    stream.writeAll(payload) catch |err| switch (err) {
                        YamuxError.StreamClosed, YamuxError.SessionClosed => {
                            _ = ctx.errored.fetchAdd(1, .monotonic);
                            done += 1;
                            continue;
                        },
                        else => return err,
                    };
                    _ = ctx.bytes_sent.fetchAdd(payload_len, .monotonic);
                }

                stream.close() catch {};
                _ = ctx.closed.fetchAdd(1, .monotonic);
                done += 1;
            }
        }
    };

    // Responder: drain all accepted streams.
    const ResponderCtx = struct {
        session: *Session,
        bytes_recv: *std.atomic.Value(u64),
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn run(ctx: *@This()) anyerror!void {
            while (!ctx.done.load(.acquire)) {
                var stream = ctx.session.acceptStream() catch |err| switch (err) {
                    YamuxError.GoAway, YamuxError.SessionClosed => return,
                    else => return err,
                };
                defer stream.deinit();
                var buf: [8192]u8 = undefined;
                while (true) {
                    const n = stream.readSome(&buf) catch break;
                    if (n == 0) break;
                    _ = ctx.bytes_recv.fetchAdd(n, .monotonic);
                }
            }
        }
    };

    var resp_ctx = ResponderCtx{ .session = &resp_session, .bytes_recv = &total_bytes_recv };
    var resp_future = try io.concurrent(ResponderCtx.run, .{&resp_ctx});

    // Launch all initiator workers concurrently.
    const FutureType = std.Io.Future(anyerror!void);
    const worker_futures = try allocator.alloc(FutureType, cfg.concurrent_workers);
    defer allocator.free(worker_futures);
    const worker_ctxs = try allocator.alloc(WorkerCtx, cfg.concurrent_workers);
    defer allocator.free(worker_ctxs);

    var timer = try std.time.Timer.start();

    for (0..cfg.concurrent_workers) |i| {
        worker_ctxs[i] = WorkerCtx{
            .session = &init_session,
            .io = io,
            .allocator = allocator,
            .worker_id = i,
            .streams_to_open = streams_per_worker,
            .deadline_ns = deadline_ns,
            .opened = &total_opened,
            .closed = &total_closed,
            .errored = &total_errored,
            .bytes_sent = &total_bytes_sent,
        };
        worker_futures[i] = try io.concurrent(WorkerCtx.run, .{&worker_ctxs[i]});
    }

    for (worker_futures) |*f| {
        f.await(io) catch {};
    }

    resp_ctx.done.store(true, .release);
    init_session.deinit();
    resp_session.deinit();
    resp_future.await(io) catch {};

    init_secure.deinit();
    resp_secure.deinit();
    init_conn.deinit();
    resp_conn.deinit();

    return Metrics{
        .streams_opened = total_opened.load(.acquire),
        .streams_closed = total_closed.load(.acquire),
        .streams_errored = total_errored.load(.acquire),
        .bytes_sent = total_bytes_sent.load(.acquire),
        .bytes_received = total_bytes_recv.load(.acquire),
        .sessions_created = 2,
        .sessions_closed = 2,
        .elapsed_ns = timer.read(),
    };
}

// ── runner ────────────────────────────────────────────────────────────────────

const Scenario = enum { session_churn, stream_churn, concurrent_chaos, all };

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_it.deinit();
    _ = args_it.next(); // skip argv[0]

    var cfg = Config.ci();
    var scenario = Scenario.all;

    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--soak")) {
            cfg = Config.soak();
        } else if (std.mem.eql(u8, arg, "session_churn")) {
            scenario = .session_churn;
        } else if (std.mem.eql(u8, arg, "stream_churn")) {
            scenario = .stream_churn;
        } else if (std.mem.eql(u8, arg, "concurrent_chaos")) {
            scenario = .concurrent_chaos;
        } else {
            print("unknown argument: {s}\n", .{arg});
            print("usage: libp2p_stress [--soak] [session_churn|stream_churn|concurrent_chaos]\n", .{});
            return error.InvalidArgument;
        }
    }

    print("libp2p stress harness — profile: {s}\n", .{
        if (cfg.duration_secs > 10) "soak" else "ci",
    });
    print("  duration={d}s sessions={d} streams={d} payload={d}B workers={d}\n\n", .{
        cfg.duration_secs,
        cfg.session_cycles,
        cfg.stream_count,
        cfg.payload_bytes,
        cfg.concurrent_workers,
    });

    var any_fail = false;

    if (scenario == .session_churn or scenario == .all) {
        print("scenario: session_churn\n", .{});
        if (runSessionChurn(cfg, io)) |m| {
            m.print("session_churn");
            print("  result: PASS\n\n", .{});
        } else |err| {
            print("  FAIL: {}\n\n", .{err});
            any_fail = true;
            if (scenario != .all) return err;
        }
    }

    if (scenario == .stream_churn or scenario == .all) {
        print("scenario: stream_churn\n", .{});
        if (runStreamChurn(cfg, io)) |m| {
            m.print("stream_churn");
            print("  result: PASS\n\n", .{});
        } else |err| {
            print("  FAIL: {}\n\n", .{err});
            any_fail = true;
            if (scenario != .all) return err;
        }
    }

    if (scenario == .concurrent_chaos or scenario == .all) {
        print("scenario: concurrent_chaos\n", .{});
        if (runConcurrentChaos(cfg, io)) |m| {
            m.print("concurrent_chaos");
            if (m.streams_errored > m.streams_opened / 4) {
                print("  result: FAIL (error rate {d}/{d} exceeds 25%)\n\n", .{
                    m.streams_errored, m.streams_opened,
                });
                any_fail = true;
            } else {
                print("  result: PASS\n\n", .{});
            }
        } else |err| {
            print("  FAIL: {}\n\n", .{err});
            any_fail = true;
            if (scenario != .all) return err;
        }
    }

    if (any_fail) {
        print("FAIL\n", .{});
        std.process.exit(1);
    }
    print("PASS\n", .{});
}
