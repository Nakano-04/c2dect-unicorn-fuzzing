const std = @import("std");

var global_io: std.Io = undefined;

fn out(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(global_io, text);
}

fn fingerprint(allocator: std.mem.Allocator, signal: []const u8, rip: []const u8, stack: []const u8) ![]u8 {
    const raw = try std.fmt.allocPrint(allocator, "{s}|{s}|{s}", .{ signal, rip, stack });
    defer allocator.free(raw);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(raw);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);
    return allocator.dupe(u8, hex[0..16]);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    global_io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) {
        try out(allocator, "uso: triage_zig <crashes.json>\n", .{});
        std.process.exit(2);
    }

    const data = try std.Io.Dir.cwd().readFileAlloc(global_io, args[1], allocator, std.Io.Limit.limited(16 * 1024 * 1024));
    defer allocator.free(data);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    var groups = std.StringHashMap(usize).init(allocator);
    defer {
        var it = groups.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        groups.deinit();
    }

    const items = parsed.value.array.items;
    for (items) |item| {
        const obj = item.object;
        const signal = obj.get("signal") orelse continue;
        const rip = obj.get("rip") orelse continue;
        const stack = obj.get("stack") orelse continue;
        const fp = try fingerprint(allocator, signal.string, rip.string, stack.string);
        const entry = try groups.getOrPut(fp);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* += 1;
    }

    try out(allocator, "{{\"total\":{d},\"unique\":{d}}}\n", .{ items.len, groups.count() });
}

test "fingerprint es estable" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = try fingerprint(gpa.allocator(), "SIGSEGV", "0x1000", "[ret]");
    defer gpa.allocator().free(a);
    const b = try fingerprint(gpa.allocator(), "SIGSEGV", "0x1000", "[ret]");
    defer gpa.allocator().free(b);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqual(@as(usize, 16), a.len);
}
