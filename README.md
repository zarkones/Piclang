# Piclang

Piclang is a C and Golang inspired, statically typed programming language that compiles to raw position-independent x86-64 shellcode, purpose-built for development of red-team implants.

Single compiled shellcode runs on both Windows and Linux. The novel approach resolves DLLs (Windows) or LibC (Linux) at run-time, allowing itself to bootstrap the standard library and allow you to write portable shellcode that works regardless of the operating system. To clarify, that doesn't mean you build one for Windows and one for Linux, instead a single shellcode works on both operating systems.

Piclang is focused on developer experience and lowers the skill level required to make the most advanced implants possible.

# Obfuscation
By default, the compiler obfuscates all strings, randomizes section names, etc... 

# Motivation
I have been researching position-independent code malware for quite some time and have grow tired of how painful it is to develop in C/C++/Zig.

Therefore, I have written a programming language that is purpose built for malware development.

Keep in mind that this is an experimental compiler.
# Examples

One small program per std package (plus the implant stuff):

    examples/bootstrap_runtime   std/runtime
    examples/touch_memory        std/mem
    examples/work_strings        std/strings
    examples/handle_files        std/file
    examples/read_env            std/env
    examples/join_paths          std/path
    examples/sleep_clocks        std/time
    examples/host_info           std/os
    examples/run_process         std/process
    examples/net_client          std/net
    examples/use_crypto          std/crypto
    examples/hash_bytes          std/hash
    examples/implant             full agent
    examples/implant_server      Go C2 CLI

    picc examples/handle_files/main.pic -o handle_files.bin -rand-sections=false
    ./harness/run_shellcode handle_files.bin

    picc examples/implant/main.pic -o implant.bin -rand-sections=false
    cd examples/implant_server && go run . -listen :8080

# Standard library reference

Import paths look like import "std/runtime". Names that start with a capital letter are exported.

Conventions I stuck to:

    Fallible calls that produce a value: (value, *u8), err == 0 means success.
    Ops that only fail: return *u8, 0 means ok.
    Heap *u8 from Alloc / most string APIs: runtime.Free when you are done.
    Owning slices: free(s). Views (subslices) do not own memory — do not free them.
    Call runtime.Init(stackHint) once before anything that needs the OS or heap.
    Do not write const x: *u8 = "..." — those pointers are currently null at runtime. Use a var.

## std/runtime

Dual-OS bootstrap: detect Linux/Windows, resolve heap, Alloc/Free.

    type PVOID = *void

    fn Init(stackHint: PVOID) -> bool
        Detect OS and wire malloc/RtlAllocateHeap. Pass main's stack frame pointer.
    fn IsLinux() -> bool
        True after Init chose Linux.
    fn IsWindows() -> bool
        True after Init chose Windows.
    fn Ready() -> bool
        Init completed and OS is known.
    fn StackHint() -> PVOID
        Pointer passed to Init (Linux link_map discovery).
    fn Alloc(n: u64) -> (PVOID, *u8)
        Heap block of n bytes (n==0 treated as 1).
    fn Free(p: PVOID)
        Free a block from Alloc. null is ignored.

## std/mem

No OS. Thin wrappers around builtins.

    fn Copy(dst: *void, src: *void, n: u64) -> *void
        memcpy; returns dst.
    fn Set(dst: *void, val: u64, n: u64) -> *void
        memset; returns dst.
    fn Equal(a: *void, b: *void, n: u64) -> bool
        memcmp == 0.

## std/strings

NUL-terminated *u8 strings. Allocating helpers need runtime.Init; free results with runtime.Free.

    fn Len(s: *u8) -> u64
        Length excluding NUL.
    fn Compare(a: *u8, b: *u8) -> bool
        Byte equality including shared null.
    fn HasPrefix(s: *u8, prefix: *u8) -> bool
    fn HasSuffix(s: *u8, suffix: *u8) -> bool
    fn Contains(s: *u8, sub: *u8) -> bool
    fn Append(a: *u8, b: *u8) -> (*u8, *u8)
        New heap string a+b.
    fn Replace(s: *u8, old: *u8, newS: *u8) -> (*u8, *u8)
        First occurrence only.
    fn ReplaceAll(s: *u8, old: *u8, newS: *u8) -> (*u8, *u8)
    fn Count(s: *u8, old: *u8) -> u64
        Non-overlapping count of old in s.

## std/file

Dual-OS file I/O. Paths are *u8 (POSIX / ANSI).

    type Handle = u64
    const INVALID
    const O_READ, O_WRITE, O_READWRITE
    const MAX_READ

    fn Open(path: *u8, mode: u64) -> (Handle, *u8)
    fn Close(h: Handle) -> *u8
    fn Read(h: Handle, buf: *u8, n: u64) -> (u64, *u8)
        Bytes read.
    fn Write(h: Handle, buf: *u8, n: u64) -> (u64, *u8)
        Bytes written.
    fn Size(h: Handle) -> (u64, *u8)
    fn Remove(path: *u8) -> *u8
    fn WriteAll(path: *u8, data: *u8, n: u64) -> *u8
        Create/truncate and write n bytes.
    fn WriteString(path: *u8, s: *u8) -> *u8
        WriteAll of a C string (no trailing NUL on disk).
    fn ReadAll(path: *u8) -> ([]u8, *u8)
        Owning slice; free(data). Note: /proc often reports size 0 — use Open+Read loop there.

## std/env

    fn Get(key: *u8) -> (*u8, *u8)
        Heap copy of value, or empty string if unset. Always Free the pointer if non-null.
    fn Lookup(key: *u8) -> (*u8, bool, *u8)
        (value, present, err). Free value when present.
    fn GetOr(key: *u8, def: *u8) -> (*u8, *u8)
        Get, or heap copy of def.
    fn Set(key: *u8, val: *u8) -> *u8
    fn Unset(key: *u8) -> *u8

## std/path

Path helpers on *u8. Allocating results: runtime.Free.

    const MAX_PATH

    fn Separator() -> u8
        '/' or '\\' from runtime OS.
    fn IsAbs(p: *u8) -> bool
    fn Base(p: *u8) -> (*u8, *u8)
    fn Dir(p: *u8) -> (*u8, *u8)
    fn Ext(p: *u8) -> (*u8, *u8)
    fn Join(a: *u8, b: *u8) -> (*u8, *u8)
    fn Clean(p: *u8) -> (*u8, *u8)

## std/time

Durations are i64 nanoseconds.

    type Duration = i64
    const Nanosecond, Microsecond, Millisecond, Second, Minute, Hour

    fn Unix(sec: i64, nsec: i64) -> i64
        Build a unix-ns timestamp.
    fn UnixSec(ns: i64) -> i64
    fn UnixNano(ns: i64) -> i64
        Identity helper.
    fn Sleep(d: Duration) -> *u8
    fn Now() -> (i64, *u8)
        Wall clock unix ns.
    fn Mono() -> (i64, *u8)
        Monotonic ns (for intervals).
    fn Since(startNs: i64) -> Duration
        Mono()-style delta from startNs.

## std/os

Host / process path helpers and a few machine facts.

    fn Hostname() -> (*u8, *u8)
    fn GetCwd() -> (*u8, *u8)
    fn GetHomeDir() -> (*u8, *u8)
        $HOME / USERPROFILE (etc).
    fn GetTempDir() -> (*u8, *u8)
    fn Arch() -> *u8
        Static "x86_64". Do not Free.
    fn OSName() -> *u8
        Static "linux" / "windows" / "unknown". Do not Free.
    fn NumCPU() -> (u64, *u8)
        Online logical CPUs.
    fn PageSize() -> (u64, *u8)
    fn TotalRAM() -> (u64, *u8)
        Physical RAM bytes (approx).
    fn PID() -> (u64, *u8)
    fn Username() -> (*u8, *u8)
    fn CPUModel() -> (*u8, *u8)
        /proc/cpuinfo model name or PROCESSOR_IDENTIFIER.

## std/process

Spawn processes, pipes, shell helpers.

    type Handle = u64
    const INVALID
    const STD_INHERIT, STD_PIPE, STD_NULL
    const MAX_OUTPUT

    struct Cmd
        program, argv, dir, env, stdin/out/err modes, cmdline, hideWindow,
        plus runtime fields (pid, exitCode, pipe ends, ...). Zero before use.

    fn Zero(c: *Cmd)
    fn Command(c: *Cmd, program: *u8)
        Zero and set program.
    fn SetArgv(c: *Cmd, argv: **u8)
    fn SetDir(c: *Cmd, dir: *u8)
    fn SetEnv(c: *Cmd, env: **u8)
    fn SetStdin(c: *Cmd, mode: u64)
    fn SetStdout(c: *Cmd, mode: u64)
    fn SetStderr(c: *Cmd, mode: u64)
    fn PipeAll(c: *Cmd)
        All three stdio modes = STD_PIPE.
    fn WriteStdin(c: *Cmd, buf: *u8, n: u64) -> (u64, *u8)
    fn ReadStdout(c: *Cmd, buf: *u8, n: u64) -> (u64, *u8)
    fn ReadStderr(c: *Cmd, buf: *u8, n: u64) -> (u64, *u8)
    fn CloseStdin(c: *Cmd)
    fn Start(c: *Cmd) -> *u8
    fn Wait(c: *Cmd) -> (i32, *u8)
        Exit code.
    fn Kill(c: *Cmd) -> *u8
    fn Release(c: *Cmd)
        Close leftover handles.
    fn Run(c: *Cmd) -> (i32, *u8)
        Start+Wait.
    fn Output(c: *Cmd) -> ([]u8, *u8)
        Run with stdout piped; free the slice.
    fn CombinedOutput(c: *Cmd) -> ([]u8, *u8)
    fn Shell(line: *u8) -> (i32, *u8)
        /bin/sh -c or cmd.exe /c.
    fn ShellOutput(line: *u8) -> ([]u8, *u8)
    fn Bash(line: *u8) -> (i32, *u8)
    fn BashOutput(line: *u8) -> ([]u8, *u8)
    fn PowerShell(line: *u8) -> (i32, *u8)
    fn PowerShellOutput(line: *u8) -> ([]u8, *u8)
    fn System(line: *u8) -> (i32, *u8)
        Alias-style shell run.
    fn SelfTest() -> (i32, *u8)
        Internal smoke.

## std/net

IPv4 TCP client + cleartext HTTP. Call net.Init() after runtime.Init.
No listen, no TLS (https:// is rejected).

    type Conn = u64
    const INVALID
    const SHUT_RD, SHUT_WR, SHUT_RDWR

    fn Init() -> *u8
        Resolve sockets / WSAStartup.
    fn IsValid(c: Conn) -> bool
    fn ParseIP(s: *u8) -> (u32, *u8)
        Dotted quad → presentation-order u32 (127.0.0.1 == 0x7F000001).
    fn IPToString(ip: u32) -> (*u8, *u8)
        Heap "a.b.c.d"; Free.
    fn DialIP(ip: u32, port: u64) -> (Conn, *u8)
    fn Resolve(host: *u8) -> (u32, *u8)
        First A record or ParseIP.
    fn ResolveAll(host: *u8, out: *u32, max: u64) -> (u64, *u8)
        Fill out[0:max]; returns count.
    fn Dial(host: *u8, port: u64) -> (Conn, *u8)
    fn Write(c: Conn, buf: *u8, n: u64) -> (u64, *u8)
    fn WriteAll(c: Conn, buf: *u8, n: u64) -> *u8
    fn Read(c: Conn, buf: *u8, n: u64) -> (u64, *u8)
    fn ReadFull(c: Conn, buf: *u8, n: u64) -> *u8
    fn Close(c: Conn) -> *u8
    fn Shutdown(c: Conn, how: u64) -> *u8
    fn SetNoDelay(c: Conn, on: bool) -> *u8
    fn SetKeepAlive(c: Conn, on: bool) -> *u8
    fn SetReuseAddr(c: Conn, on: bool) -> *u8
    fn SetRecvTimeout(c: Conn, ms: u64) -> *u8
    fn SetSendTimeout(c: Conn, ms: u64) -> *u8

    struct Response
        status: u32
        body: *u8
        bodyLen: u64

    fn FreeResponse(r: *Response)
        Free body and the heap Response from Get/Post/Do.
    fn Get(url: *u8) -> (*Response, *u8)
        Heap Response; FreeResponse.
    fn Post(url: *u8, contentType: *u8, body: *u8, bodyLen: u64) -> (*Response, *u8)
    fn Do(method: *u8, url: *u8, headers: **u8, body: *u8, bodyLen: u64) -> (*Response, *u8)
        headers is a null-terminated list of "Name: value" C strings, or null.

## std/crypto

Freestanding. No OS.

    struct RC4
        S-box + i,j for stream cipher state.

    fn HashA(s: *u8) -> u32
        djb2 uppercase (same idea as __hash).
    fn Equal(a: *u8, b: *u8, n: u64) -> bool
        Constant-time-ish compare of n bytes.
    fn XORBytes(data: *u8, n: u64, key: *u8, keylen: u64)
        In-place repeating-key XOR.
    fn XOR(dst: *u8, src: *u8, n: u64, key: *u8, keylen: u64)
        XOR into dst.
    fn RC4Init(st: *RC4, key: *u8, keylen: u64)
    fn RC4XOR(st: *RC4, data: *u8, n: u64)
        Encrypt/decrypt in place.
    fn HexEncode(data: *u8, n: u64) -> (*u8, *u8)
        Heap hex C string; Free.
    fn HexDecode(hex: *u8) -> (*u8, u64, *u8)
        Heap bytes + length; Free.
    fn Base64Encode(data: *u8, n: u64) -> (*u8, *u8)
        Standard alphabet; Free.
    fn Base64Decode(s: *u8) -> (*u8, u64, *u8)
        Free.

## std/hash

Name hash + digests. Digest one-shots write into a caller buffer.

    const MD5_SIZE = 16
    const SHA1_SIZE = 20
    const SHA256_SIZE = 32

    fn String(s: *u8) -> u32
        djb2 uppercase via __hash (API/module name hashing).
    fn MD5(data: *u8, n: u64, out: *u8) -> *u8
        out must be MD5_SIZE bytes.
    fn SHA1(data: *u8, n: u64, out: *u8) -> *u8
    fn SHA256(data: *u8, n: u64, out: *u8) -> *u8
    fn SumMD5(data: *u8, n: u64) -> (*u8, *u8)
        Heap digest; Free.
    fn SumSHA1(data: *u8, n: u64) -> (*u8, *u8)
    fn SumSHA256(data: *u8, n: u64) -> (*u8, *u8)

## std/linux/resolve

PEB-less Linux module/symbol resolve via link_map (used by runtime and friends).

    fn Probe(stackHint: PVOID) -> bool
        Looks like we can find r_debug.
    fn FindRDebug(stackHint: PVOID) -> PVOID
    fn Module(nameHash: u32, stackHint: PVOID) -> PVOID
        Base of a loaded .so by djb2 hash of basename.
    fn Symbol(moduleBase: PVOID, funcHash: u32) -> PVOID
        Export by djb2 hash.

## std/windows/resolve

PEB walk for modules/exports.

    fn Probe() -> bool
    fn ProcessHeap() -> PVOID
    fn Module(want: u32) -> PVOID
        Module base by hash of name.
    fn Symbol(base: PVOID, want: u32) -> PVOID
        Export by hash.
