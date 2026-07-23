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