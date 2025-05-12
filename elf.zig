const std = @import("std");
const mem = std.mem;

// Common ELF types
pub const Elf32_Addr = u32;
pub const Elf32_Off = u32;
pub const Elf32_Half = u16;
pub const Elf32_Word = u32;
pub const Elf32_Sword = i32;

pub const Elf64_Addr = u64;
pub const Elf64_Off = u64;
pub const Elf64_Half = u16;
pub const Elf64_Word = u32;
pub const Elf64_Sword = i32;
pub const Elf64_Xword = u64;
pub const Elf64_Sxword = i64;
pub const Elf64_Byte = u8;

// ELF identification
pub const ELFMAG = "\x7FELF";
pub const ELFCLASS32 = 1;
pub const ELFCLASS64 = 2;
pub const ELFDATA2LSB = 1;
pub const ELFDATA2MSB = 2;

// ELF types
pub const ET_NONE = 0;
pub const ET_REL = 1;
pub const ET_EXEC = 2;
pub const ET_DYN = 3;
pub const ET_CORE = 4;

// Program header types
pub const PT_NULL = 0;
pub const PT_LOAD = 1;
pub const PT_DYNAMIC = 2;
pub const PT_INTERP = 3;
pub const PT_NOTE = 4;
pub const PT_SHLIB = 5;
pub const PT_PHDR = 6;
pub const PT_TLS = 7;

// 32-bit ELF structures
pub const Elf32_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: Elf32_Half,
    e_machine: Elf32_Half,
    e_version: Elf32_Word,
    e_entry: Elf32_Addr,
    e_phoff: Elf32_Off,
    e_shoff: Elf32_Off,
    e_flags: Elf32_Word,
    e_ehsize: Elf32_Half,
    e_phentsize: Elf32_Half,
    e_phnum: Elf32_Half,
    e_shentsize: Elf32_Half,
    e_shnum: Elf32_Half,
    e_shstrndx: Elf32_Half,
};

pub const Elf32_Phdr = extern struct {
    p_type: Elf32_Word,
    p_offset: Elf32_Off,
    p_vaddr: Elf32_Addr,
    p_paddr: Elf32_Addr,
    p_filesz: Elf32_Word,
    p_memsz: Elf32_Word,
    p_flags: Elf32_Word,
    p_align: Elf32_Word,
};

// 64-bit ELF structures
pub const Elf64_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: Elf64_Half,
    e_machine: Elf64_Half,
    e_version: Elf64_Word,
    e_entry: Elf64_Addr,
    e_phoff: Elf64_Off,
    e_shoff: Elf64_Off,
    e_flags: Elf64_Word,
    e_ehsize: Elf64_Half,
    e_phentsize: Elf64_Half,
    e_phnum: Elf64_Half,
    e_shentsize: Elf64_Half,
    e_shnum: Elf64_Half,
    e_shstrndx: Elf64_Half,
};

pub const Elf64_Phdr = extern struct {
    p_type: Elf64_Word,
    p_flags: Elf64_Word,
    p_offset: Elf64_Off,
    p_vaddr: Elf64_Addr,
    p_paddr: Elf64_Addr,
    p_filesz: Elf64_Xword,
    p_memsz: Elf64_Xword,
    p_align: Elf64_Xword,
};

pub const ElfState = struct {
    is_64bit: bool = false,
    is_little_endian: bool = true,
};

fn read_bytes(reader: anytype, comptime T: type, is_little_endian: bool) !T {
    const bytes = try reader.readBytesNoEof(@sizeOf(T));
    var result: T = 0;

    if (is_little_endian) {
        inline for (bytes, 0..) |byte, i| {
            result |= @as(T, byte) << @intCast(i * 8);
        }
    } else {
        inline for (bytes, 0..) |byte, i| {
            result |= @as(T, byte) << @intCast((@sizeOf(T) - 1 - i) * 8);
        }
    }
    return result;
}

fn write_bytes(writer: anytype, value: anytype, is_little_endian: bool) !void {
    const T = @TypeOf(value);
    var bytes: [@sizeOf(T)]u8 = undefined;

    if (is_little_endian) {
        inline for (&bytes, 0..) |*byte, i| {
            byte.* = @truncate(value >> @intCast(i * 8));
        }
    } else {
        inline for (&bytes, 0..) |*byte, i| {
            byte.* = @truncate(value >> @intCast((@sizeOf(T) - 1 - i) * 8));
        }
    }
    try writer.writeAll(&bytes);
}

pub fn read_elf_header(reader: anytype, state: *ElfState) !Elf64_Ehdr {
    var ident: [16]u8 = undefined;
    _ = try reader.readAll(&ident);

    if (!mem.eql(u8, ident[0..4], ELFMAG)) {
        return error.InvalidElfMagic;
    }

    state.is_64bit = ident[4] == ELFCLASS64;
    state.is_little_endian = ident[5] == ELFDATA2LSB;

    var ehdr: Elf64_Ehdr = undefined;
    @memcpy(ehdr.e_ident[0..], &ident);

    ehdr.e_type = try read_bytes(reader, Elf64_Half, state.is_little_endian);
    ehdr.e_machine = try read_bytes(reader, Elf64_Half, state.is_little_endian);
    ehdr.e_version = try read_bytes(reader, Elf64_Word, state.is_little_endian);

    if (state.is_64bit) {
        ehdr.e_entry = try read_bytes(reader, Elf64_Addr, state.is_little_endian);
        ehdr.e_phoff = try read_bytes(reader, Elf64_Off, state.is_little_endian);
        ehdr.e_shoff = try read_bytes(reader, Elf64_Off, state.is_little_endian);
    } else {
        ehdr.e_entry = try read_bytes(reader, Elf32_Addr, state.is_little_endian);
        ehdr.e_phoff = try read_bytes(reader, Elf32_Off, state.is_little_endian);
        ehdr.e_shoff = try read_bytes(reader, Elf32_Off, state.is_little_endian);
    }

    ehdr.e_flags = try read_bytes(reader, Elf64_Word, state.is_little_endian);
    ehdr.e_ehsize = try read_bytes(reader, Elf64_Half, state.is_little_endian);
    ehdr.e_phentsize = try read_bytes(reader, Elf64_Half, state.is_little_endian);
    ehdr.e_phnum = try read_bytes(reader, Elf64_Half, state.is_little_endian);
    ehdr.e_shentsize = try read_bytes(reader, Elf64_Half, state.is_little_endian);
    ehdr.e_shnum = try read_bytes(reader, Elf64_Half, state.is_little_endian);
    ehdr.e_shstrndx = try read_bytes(reader, Elf64_Half, state.is_little_endian);

    return ehdr;
}

pub fn write_elf_header(writer: anytype, ehdr: *const Elf64_Ehdr, state: *ElfState) !void {
    try writer.writeAll(&ehdr.e_ident);
    try write_bytes(writer, ehdr.e_type, state.is_little_endian);
    try write_bytes(writer, ehdr.e_machine, state.is_little_endian);
    try write_bytes(writer, ehdr.e_version, state.is_little_endian);

    if (state.is_64bit) {
        try write_bytes(writer, ehdr.e_entry, state.is_little_endian);
        try write_bytes(writer, ehdr.e_phoff, state.is_little_endian);
        try write_bytes(writer, ehdr.e_shoff, state.is_little_endian);
    } else {
        try write_bytes(writer, @as(Elf32_Addr, @truncate(ehdr.e_entry)), state.is_little_endian);
        try write_bytes(writer, @as(Elf32_Off, @truncate(ehdr.e_phoff)), state.is_little_endian);
        try write_bytes(writer, @as(Elf32_Off, @truncate(ehdr.e_shoff)), state.is_little_endian);
    }

    try write_bytes(writer, ehdr.e_flags, state.is_little_endian);
    try write_bytes(writer, ehdr.e_ehsize, state.is_little_endian);
    try write_bytes(writer, ehdr.e_phentsize, state.is_little_endian);
    try write_bytes(writer, ehdr.e_phnum, state.is_little_endian);
    try write_bytes(writer, ehdr.e_shentsize, state.is_little_endian);
    try write_bytes(writer, ehdr.e_shnum, state.is_little_endian);
    try write_bytes(writer, ehdr.e_shstrndx, state.is_little_endian);
}

pub fn read_program_headers(reader: anytype, phdrs: []Elf64_Phdr, count: u16, state: *ElfState) !void {
    if (phdrs.len < count) {
        return error.BufferTooSmall;
    }

    for (0..count) |i| {
        phdrs[i].p_type = try read_bytes(reader, Elf64_Word, state.is_little_endian);

        if (state.is_64bit) {
            phdrs[i].p_flags = try read_bytes(reader, Elf64_Word, state.is_little_endian);
            inline for (.{ "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_align" }) |field| {
                @field(phdrs[i], field) = try read_bytes(reader, Elf64_Xword, state.is_little_endian);
            }
        } else {
            inline for (.{ "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz" }) |field| {
                @field(phdrs[i], field) = try read_bytes(reader, Elf32_Word, state.is_little_endian);
            }
            phdrs[i].p_flags = try read_bytes(reader, Elf32_Word, state.is_little_endian);
            phdrs[i].p_align = try read_bytes(reader, Elf32_Word, state.is_little_endian);
        }
    }
}

pub fn write_program_headers(writer: anytype, phdrs: []const Elf64_Phdr, state: *ElfState) !void {
    for (phdrs) |phdr| {
        try write_bytes(writer, phdr.p_type, state.is_little_endian);

        if (state.is_64bit) {
            try write_bytes(writer, phdr.p_flags, state.is_little_endian);
            inline for (.{ "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz", "p_align" }) |field| {
                try write_bytes(writer, @field(phdr, field), state.is_little_endian);
            }
        } else {
            inline for (.{ "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz" }) |field| {
                try write_bytes(writer, @as(Elf32_Word, @truncate(@field(phdr, field))), state.is_little_endian);
            }
            try write_bytes(writer, phdr.p_flags, state.is_little_endian);
            try write_bytes(writer, @as(Elf32_Word, @truncate(phdr.p_align)), state.is_little_endian);
        }
    }
}
