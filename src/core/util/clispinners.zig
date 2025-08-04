const std = @import("std");

/// Spinner represents an animated loading indicator with frames and timing
pub const Spinner = struct {
    name: []const u8,
    interval: u32, // milliseconds between frames
    frames: []const []const u8,
};

/// Terminal control functions for spinner rendering
pub const Terminal = struct {
    /// Hide cursor using ANSI escape sequence
    pub fn hideCursor() void {
        std.io.getStdOut().writer().print("\x1b[?25l", .{}) catch {};
    }

    /// Show cursor using ANSI escape sequence
    pub fn showCursor() void {
        std.io.getStdOut().writer().print("\x1b[?25h", .{}) catch {};
    }

    /// Clear current line
    pub fn clearLine() void {
        std.io.getStdOut().writer().print("\r\x1b[K", .{}) catch {};
    }

    /// Move cursor to beginning of line
    pub fn carriageReturn() void {
        std.io.getStdOut().writer().print("\r", .{}) catch {};
    }
};

/// SpinnerRenderer manages the animation of a single spinner
pub const SpinnerRenderer = struct {
    spinner: Spinner,
    current_frame: usize,
    timer: std.time.Timer,
    message: []const u8,
    is_running: bool,

    pub fn init(spinner: Spinner, message: []const u8) !SpinnerRenderer {
        return SpinnerRenderer{
            .spinner = spinner,
            .current_frame = 0,
            .timer = try std.time.Timer.start(),
            .message = message,
            .is_running = false,
        };
    }

    pub fn start(self: *SpinnerRenderer) !void {
        self.is_running = true;
        Terminal.hideCursor();
        try self.render();
    }

    pub fn stop(self: *SpinnerRenderer) void {
        self.is_running = false;
        Terminal.clearLine();
        Terminal.showCursor();
    }

    pub fn stopWithMessage(self: *SpinnerRenderer, message: []const u8) void {
        self.is_running = false;
        Terminal.clearLine();
        std.io.getStdOut().writer().print("{s}\n", .{message}) catch {};
        Terminal.showCursor();
    }

    pub fn update(self: *SpinnerRenderer) !void {
        if (!self.is_running) return;

        const elapsed = self.timer.read() / std.time.ns_per_ms;
        if (elapsed >= self.spinner.interval) {
            self.current_frame = (self.current_frame + 1) % self.spinner.frames.len;
            self.timer.reset();
            try self.render();
        }
    }

    fn render(self: *SpinnerRenderer) !void {
        const stdout = std.io.getStdOut().writer();
        Terminal.carriageReturn();
        try stdout.print("{s} {s}", .{
            self.spinner.frames[self.current_frame],
            self.message,
        });
    }
};

// Popular spinner definitions
pub const dots = Spinner{
    .name = "dots",
    .interval = 80,
    .frames = &[_][]const u8{ "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" },
};

pub const dots2 = Spinner{
    .name = "dots2",
    .interval = 80,
    .frames = &[_][]const u8{ "⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷" },
};

pub const dots3 = Spinner{
    .name = "dots3",
    .interval = 80,
    .frames = &[_][]const u8{ "⠋", "⠙", "⠚", "⠞", "⠖", "⠦", "⠴", "⠲", "⠳", "⠓" },
};

pub const line = Spinner{
    .name = "line",
    .interval = 130,
    .frames = &[_][]const u8{ "-", "\\", "|", "/" },
};

pub const line2 = Spinner{
    .name = "line2",
    .interval = 100,
    .frames = &[_][]const u8{ "⠂", "-", "–", "—", "–", "-" },
};

pub const pipe = Spinner{
    .name = "pipe",
    .interval = 100,
    .frames = &[_][]const u8{ "┤", "┘", "┴", "└", "├", "┌", "┬", "┐" },
};

pub const simpleDots = Spinner{
    .name = "simpleDots",
    .interval = 400,
    .frames = &[_][]const u8{ ".  ", ".. ", "...", "   " },
};

pub const simpleDotsScrolling = Spinner{
    .name = "simpleDotsScrolling",
    .interval = 200,
    .frames = &[_][]const u8{ ".  ", ".. ", "...", " ..", "  .", "   " },
};

pub const star = Spinner{
    .name = "star",
    .interval = 70,
    .frames = &[_][]const u8{ "✶", "✸", "✹", "✺", "✹", "✷" },
};

pub const star2 = Spinner{
    .name = "star2",
    .interval = 80,
    .frames = &[_][]const u8{ "+", "x", "*" },
};

pub const arc = Spinner{
    .name = "arc",
    .interval = 100,
    .frames = &[_][]const u8{ "◜", "◠", "◝", "◞", "◡", "◟" },
};

pub const circle = Spinner{
    .name = "circle",
    .interval = 120,
    .frames = &[_][]const u8{ "◡", "⊙", "◠" },
};

pub const circleQuarters = Spinner{
    .name = "circleQuarters",
    .interval = 120,
    .frames = &[_][]const u8{ "◴", "◷", "◶", "◵" },
};

pub const circleHalves = Spinner{
    .name = "circleHalves",
    .interval = 50,
    .frames = &[_][]const u8{ "◐", "◓", "◑", "◒" },
};

pub const arrow = Spinner{
    .name = "arrow",
    .interval = 100,
    .frames = &[_][]const u8{ "←", "↖", "↑", "↗", "→", "↘", "↓", "↙" },
};

pub const arrow2 = Spinner{
    .name = "arrow2",
    .interval = 80,
    .frames = &[_][]const u8{ "⬆️ ", "↗️ ", "➡️ ", "↘️ ", "⬇️ ", "↙️ ", "⬅️ ", "↖️ " },
};

pub const arrow3 = Spinner{
    .name = "arrow3",
    .interval = 120,
    .frames = &[_][]const u8{ "▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸" },
};

pub const bouncingBar = Spinner{
    .name = "bouncingBar",
    .interval = 80,
    .frames = &[_][]const u8{
        "[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]",
        "[  ==]", "[   =]", "[    ]", "[   =]", "[  ==]",
        "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]",
    },
};

pub const bouncingBall = Spinner{
    .name = "bouncingBall",
    .interval = 80,
    .frames = &[_][]const u8{
        "( ●    )", "(  ●   )", "(   ●  )", "(    ● )", "(     ●)",
        "(    ● )", "(   ●  )", "(  ●   )", "( ●    )", "(●     )",
    },
};

pub const clock = Spinner{
    .name = "clock",
    .interval = 100,
    .frames = &[_][]const u8{ "🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚", "🕛" },
};

pub const earth = Spinner{
    .name = "earth",
    .interval = 180,
    .frames = &[_][]const u8{ "🌍", "🌎", "🌏" },
};

pub const moon = Spinner{
    .name = "moon",
    .interval = 80,
    .frames = &[_][]const u8{ "🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘" },
};

pub const hearts = Spinner{
    .name = "hearts",
    .interval = 100,
    .frames = &[_][]const u8{ "💛", "💙", "💜", "💚", "❤️" },
};

// Creative blockchain-themed spinners not in the original repo!

pub const blockchain = Spinner{
    .name = "blockchain",
    .interval = 120,
    .frames = &[_][]const u8{
        "    ",
        "[💯]",
        "[💯]-",
        "[💯]-[💯]",
        "[💯]-[💯]-",
        "[💯]-[💯]-[💯]",
        "[💯]-[💯]-[💯]-[💯]",
    },
};

pub const mining = Spinner{
    .name = "mining",
    .interval = 100,
    .frames = &[_][]const u8{ "⛏️ ", "⛏️.", "⛏️..", "⛏️...", "💎", "✨", "⛏️ " },
};

pub const coin = Spinner{
    .name = "coin",
    .interval = 80,
    .frames = &[_][]const u8{ "🪙 ", " 🪙", "  🪙", " 🪙 ", "🪙  ", "🪙 ", "💰", "🪙 " },
};

pub const network = Spinner{
    .name = "network",
    .interval = 100,
    .frames = &[_][]const u8{
        "📡    ",
        "📡 •  ",
        "📡 •• ",
        "📡 •••",
        "📡 •• ",
        "📡 •  ",
    },
};

pub const lock = Spinner{
    .name = "lock",
    .interval = 150,
    .frames = &[_][]const u8{ "🔓", "🔒", "🔐", "🔒" },
};

pub const binary = Spinner{
    .name = "binary",
    .interval = 80,
    .frames = &[_][]const u8{ "0000", "0001", "0010", "0100", "1000", "1001", "1010", "1100", "1111", "0111", "0011", "0001" },
};

pub const matrix = Spinner{
    .name = "matrix",
    .interval = 100,
    .frames = &[_][]const u8{ "╔══╗", "║10║", "║01║", "╚══╝", "╔══╗", "║01║", "║10║", "╚══╝" },
};

pub const blocks = Spinner{
    .name = "blocks",
    .interval = 120,
    .frames = &[_][]const u8{ "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃", "▂" },
};

pub const lightning = Spinner{
    .name = "lightning",
    .interval = 100,
    .frames = &[_][]const u8{ "⚡", "💥", "✨", "⚡", "🌟", "⚡" },
};

pub const zen = Spinner{
    .name = "zen",
    .interval = 200,
    .frames = &[_][]const u8{ "☯️ ", " ☯️", "  ☯️", " ☯️ ", "☯️  ", "☯️ ", "☮️ ", "☯️ " },
};

pub const hexagon = Spinner{
    .name = "hexagon",
    .interval = 100,
    .frames = &[_][]const u8{ "⬡", "⬢", "⬡", "⬢", "⬡", "⬢" },
};

pub const pulse = Spinner{
    .name = "pulse",
    .interval = 100,
    .frames = &[_][]const u8{ "·", "•", "●", "●", "•", "·", " ", "·" },
};

pub const wave = Spinner{
    .name = "wave",
    .interval = 100,
    .frames = &[_][]const u8{ "▁▂▃", "▂▃▄", "▃▄▅", "▄▅▆", "▅▆▇", "▆▇█", "▇█▇", "█▇▆", "▇▆▅", "▆▅▄", "▅▄▃", "▄▃▂", "▃▂▁" },
};

pub const rocket = Spinner{
    .name = "rocket",
    .interval = 120,
    .frames = &[_][]const u8{ "🚀     ", " 🚀    ", "  🚀   ", "   🚀  ", "    🚀 ", "     🚀", "    🚀🔥", "   🚀🔥 ", "  🚀🔥  ", " 🚀🔥   ", "🚀🔥    " },
};

pub const dna = Spinner{
    .name = "dna",
    .interval = 100,
    .frames = &[_][]const u8{ "🧬", "🔬", "🧪", "⚗️", "🧬", "🔭", "🧬" },
};

// All available spinners
pub const all_spinners = [_]*const Spinner{
    &dots,
    &dots2,
    &dots3,
    &line,
    &line2,
    &pipe,
    &simpleDots,
    &simpleDotsScrolling,
    &star,
    &star2,
    &arc,
    &circle,
    &circleQuarters,
    &circleHalves,
    &arrow,
    &arrow2,
    &arrow3,
    &bouncingBar,
    &bouncingBall,
    &clock,
    &earth,
    &moon,
    &hearts,
    // Creative blockchain-themed spinners
    &blockchain,
    &mining,
    &coin,
    &network,
    &lock,
    &binary,
    &matrix,
    &blocks,
    &lightning,
    &zen,
    &hexagon,
    &pulse,
    &wave,
    &rocket,
    &dna,
};

/// Get spinner by name
pub fn getSpinner(name: []const u8) ?Spinner {
    for (all_spinners) |spinner| {
        if (std.mem.eql(u8, spinner.name, name)) {
            return spinner.*;
        }
    }
    return null;
}

/// Get a random spinner
pub fn getRandomSpinner() Spinner {
    var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
    const random = prng.random();
    const index = random.intRangeAtMost(usize, 0, all_spinners.len - 1);
    return all_spinners[index].*;
}

// Example usage function
pub fn example() !void {
    var renderer = try SpinnerRenderer.init(dots, "Loading...");
    try renderer.start();

    // Simulate work
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        try renderer.update();
        std.time.sleep(100 * std.time.ns_per_ms);
    }

    renderer.stopWithMessage("✅ Done!");
}

test "spinner lookup" {
    const spinner = getSpinner("dots");
    try std.testing.expect(spinner != null);
    try std.testing.expectEqualStrings("dots", spinner.?.name);
}

test "random spinner" {
    const spinner = getRandomSpinner();
    try std.testing.expect(spinner.frames.len > 0);
    try std.testing.expect(spinner.interval > 0);
}
