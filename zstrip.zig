const std = @import("std");
const elf = @import("elf.zig");
const os = std.os;
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const process = std.process;

const TRUE = 1;
const FALSE = 0;

const help_text =
    \\Usage: zstrip [OPTIONS] FILE...
    \\Remove all nonessential bytes from executable ELF files.
    \\
    \\  -z, --zeroes        Also discard trailing zero bytes.
    \\      --help          Display this help and exit.
    \\      --version       Display version information and exit.
;

const version_text =
    \\zstrip: A Zig port of sstrip
    \\Copyright (C) 2025 by Valters Tomsons <valters at tomsons dot me>
    \\
    \\Original license:
    \\
    \\sstrip, version 2.1
    \\Copyright (C) 1999,2011 by Brian Raiter <breadbox@muppetlabs.com>
    \\License GPLv2+: GNU GPL version 2 or later.
    \\This is free software; you are free to change and redistribute it.
    \\There is NO WARRANTY, to the extent permitted by law.
;

const ProgramState = struct {
    do_zero_trunc: bool = false,
    filename: []const u8 = undefined,
    file: fs.File = undefined,
    ehdr: elf.Elf64_Ehdr = undefined,
    phdrs: []elf.Elf64_Phdr = undefined,
    new_size: u64 = 0,
    allocator: mem.Allocator,
    elf_state: elf.ElfState = .{},
};

fn err(state: *ProgramState, errmsg: []const u8) !void {
    std.debug.print("{s}: {s}: {s}\n", .{ state.filename, state.filename, errmsg });
    return error.OperationFailed;
}

fn read_elf_header(state: *ProgramState) !void {
    const reader = state.file.reader();
    state.ehdr = try elf.read_elf_header(reader, &state.elf_state);

    if (state.ehdr.e_type != elf.ET_EXEC and state.ehdr.e_type != elf.ET_DYN) {
        return err(state, "not an executable or shared-object library.");
    }
}

fn read_phdr_table(state: *ProgramState) !void {
    if (state.ehdr.e_phoff == 0 or state.ehdr.e_phnum == 0) {
        return err(state, "ELF file has no program header table.");
    }

    state.phdrs = try state.allocator.alloc(elf.Elf64_Phdr, state.ehdr.e_phnum);
    errdefer state.allocator.free(state.phdrs);

    const reader = state.file.reader();
    try elf.read_program_headers(reader, state.phdrs, state.ehdr.e_phnum, &state.elf_state);
}

fn get_memory_size(state: *ProgramState) !void {
    var size: u64 = state.ehdr.e_phoff + state.ehdr.e_phnum * @sizeOf(elf.Elf64_Phdr);
    if (size < state.ehdr.e_ehsize) {
        size = state.ehdr.e_ehsize;
    }

    for (state.phdrs) |phdr| {
        if (phdr.p_type != elf.PT_NULL) {
            const n = phdr.p_offset + phdr.p_filesz;
            if (n > size) {
                size = n;
            }
        }
    }

    state.new_size = size;
}

fn truncate_zeros(state: *ProgramState) !void {
    if (!state.do_zero_trunc) return;

    var size = state.new_size;
    var buffer: [1024]u8 = undefined;

    while (size > 0) {
        const n = @min(buffer.len, size);
        try state.file.seekTo(size - n);
        _ = try state.file.read(&buffer);

        var i: usize = n;
        while (i > 0) {
            i -= 1;
            if (buffer[i] != 0) break;
            size -= 1;
        }
        if (i > 0) break;
    }

    if (size == 0) {
        return err(state, "ELF file is completely blank!");
    }

    state.new_size = size;
}

fn modify_headers(state: *ProgramState) !void {
    if (state.ehdr.e_shoff >= state.new_size) {
        state.ehdr.e_shoff = 0;
        state.ehdr.e_shnum = 0;
        state.ehdr.e_shstrndx = 0;
    }

    for (state.phdrs) |*phdr| {
        if (phdr.p_offset >= state.new_size) {
            phdr.p_offset = state.new_size;
            phdr.p_filesz = 0;
        } else if (phdr.p_offset + phdr.p_filesz > state.new_size) {
            phdr.p_filesz = state.new_size - phdr.p_offset;
        }
    }
}

fn commit_changes(state: *ProgramState) !void {
    try state.file.seekTo(0);
    try elf.write_elf_header(state.file.writer(), &state.ehdr, &state.elf_state);

    try state.file.seekTo(state.ehdr.e_phoff);
    try elf.write_program_headers(state.file.writer(), state.phdrs, &state.elf_state);

    const min_size = state.ehdr.e_phoff + state.ehdr.e_phnum * state.ehdr.e_phentsize;
    if (state.new_size < min_size) {
        state.new_size = min_size;
    }

    try state.file.setEndPos(state.new_size);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = ProgramState{
        .allocator = allocator,
    };

    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);

    if (args.len == 1) {
        try io.getStdOut().writeAll(help_text);
        return;
    }

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.eql(u8, arg, "-z") or mem.eql(u8, arg, "--zeroes")) {
            state.do_zero_trunc = true;
        } else if (mem.eql(u8, arg, "--help")) {
            try io.getStdOut().writeAll(help_text);
            return;
        } else if (mem.eql(u8, arg, "--version")) {
            try io.getStdOut().writeAll(version_text);
            return;
        } else if (arg[0] == '-') {
            std.debug.print("Try --help for more information.\n", .{});
            return error.InvalidArgument;
        } else {
            state.filename = arg;

            const file = fs.cwd().openFile(state.filename, .{ .mode = .read_write }) catch |open_err| {
                switch (open_err) {
                    error.FileNotFound => {
                        std.debug.print("No such file: {s}\n", .{state.filename});
                        return;
                    },
                    error.FileBusy => {
                        std.debug.print("File is busy: {s}\n", .{state.filename});
                        return;
                    },
                    else => return open_err,
                }
            };

            defer file.close();
            state.file = file;

            read_elf_header(&state) catch |e| {
                std.debug.print("Error reading ELF header: {}\n", .{e});
                return;
            };

            read_phdr_table(&state) catch |e| {
                std.debug.print("Error reading program headers: {}\n", .{e});
                return;
            };
            defer state.allocator.free(state.phdrs);

            get_memory_size(&state) catch |e| {
                std.debug.print("Error getting memory size: {}\n", .{e});
                return;
            };

            truncate_zeros(&state) catch |e| {
                std.debug.print("Error truncating zeros: {}\n", .{e});
                return;
            };

            modify_headers(&state) catch |e| {
                std.debug.print("Error modifying headers: {}\n", .{e});
                return;
            };

            commit_changes(&state) catch |e| {
                std.debug.print("Error committing changes: {}\n", .{e});
                return;
            };

            std.debug.print("Successfully stripped {s}\n", .{state.filename});
        }
    }
}
