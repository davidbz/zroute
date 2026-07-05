const std = @import("std");
const posix = std.posix;

/// The listening socket's fd, stashed so the signal handler (which can't
/// take arguments or capture context) can reach it. Set once by `install`
/// before any signal can arrive; read-only from then on.
var listen_fd: std.atomic.Value(posix.fd_t) = .init(-1);

/// Installs a `SIGTERM`/`SIGINT` handler that triggers a graceful shutdown by
/// calling `shutdown(2)` directly on the listening socket. Per
/// `Io.net.Server.accept`'s documented contract, this makes any blocked or
/// future `accept()` call return `error.SocketNotListening` — see the doc
/// comment on `Listener.run` for how that's turned into a clean drain
/// trigger.
///
/// POSIX/Linux-only, matching the rest of the networking code's posture
/// (e.g. `have_accept4` in the resolver/listener path) — no signal handling
/// is installed on other targets.
pub fn install(fd: posix.fd_t) void {
    listen_fd.store(fd, .release);

    const act: posix.Sigaction = .{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.RESTART,
    };
    posix.sigaction(.TERM, &act, null);
    posix.sigaction(.INT, &act, null);
}

/// Async-signal-safe by construction: reads an atomic and issues one raw
/// `shutdown` syscall directly (bypassing `Io.Threaded`'s accept/shutdown
/// wrappers, which track per-thread cancellation state that isn't safe to
/// re-enter from a handler that may have interrupted that same bookkeeping
/// mid-update). No logging, no allocation, nothing else.
///
/// `SA.RESTART` (set in `install`) means this signal can land on any thread
/// — including one blocked in a live connection's read/write — without
/// disrupting it: the kernel transparently resumes that thread's own
/// syscall, since this handler only ever touches the listening socket's fd.
fn handleShutdownSignal(sig: posix.SIG) callconv(.c) void {
    _ = sig;
    const fd = listen_fd.load(.acquire);
    if (fd < 0) return;
    _ = std.os.linux.shutdown(fd, posix.SHUT.RDWR);
}

/// Clears the stashed fd once the listening socket is closed, so a second
/// signal landing after teardown can't `shutdown(2)` a reused fd number.
pub fn reset() void {
    listen_fd.store(-1, .release);
}
