# zuper-strip

zstrip is a small utility that removes as much as possible from an ELF file without affecting the file's memory image.

This is a direct port of `super-strip` and `lib-elfrw` from [Muppetlabs' ELF kickers collection](https://www.muppetlabs.com/~breadbox/software/elfkickers.html) to Zig, maintaining all original functionality and compatibility with the original `sstrip version 2.1`.

## Usage

1. Download latest release binary [from here](https://github.com/valters-tomsons/zuper-strip/releases)
1. Extract the downloaded archive
2. `./zstrip --help`

* Provided binaries are statically linked against musl-libc, so they should work on any Linux distribution with kernel version [2.6.39 or newer](https://wiki.musl-libc.org/supported-platforms.html).
* *Should* work with both 32-bit and 64-bit ELF binaries, regardless of host architecture.
* Only x86_64 binaries are provided, feel free to change `build.zig` to build for other architectures (see [Building](#building) section).

## Building

1. Install zig `0.13.0`
2. Run `zig build`
3. `./zig-out/bin/zstrip --help`

## Explanation

Most ELF executables are built with both a program header table and a section header table. However, only the former is required in order
for the OS to load, link and execute a program. sstrip attempts to extract the ELF header, the program header table, and its contents,
leaving everything else in the bit bucket. It can only remove parts of the file that occur at the end, after the parts to be saved. However,
this almost always includes the section header table, along with a few other sections that are not involved in program loading and execution.

It should be noted that most programs that work with ELF files are dependent on the section header table as an index to the file's
contents. Thus, utilities such as gdb and objdump will often have limited functionality when working with an executable with no section
header table. Some other utilities may refuse to work with them at all.

sstrip is at heart a very simple program. It depends upon the common practice of putting the parts of the file that contribute to the
memory image at the front, and the remaining material at the end. This permits it to discard the latter material without affecting file
offsets and memory addresses in what remains. Of course, the ELF standard permits files to be organized in almost any order, so if a
pathological linker decided to put the program segment header table at the end of the file, sstrip would be unable to remove anything.