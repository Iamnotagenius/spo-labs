{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  nativeBuildInputs = [
    cmake
  ];
  buildInputs = [
    clang-tools bear antlr3 libantlr3c nasm xed libunwind gdb
  ];
}
