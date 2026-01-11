{ pkgs, ... }:

{
  # https://devenv.sh/packages/
  packages = with pkgs; [
    git
    bpftools
    clangStdenv
    elfutils
    include-what-you-use
    libbfd
    libcap
    libelf
    llvm
    checkmake
    mdformat
    nixfmt-classic
  ];

  # https://devenv.sh/languages/
  languages.c.enable = true;

  # https://devenv.sh/scripts/
  scripts = {
    build.exec = "make";
    clean.exec = "make clean";
    lint.exec = ''
      checkmake src/Makefile
      git ls-files --cached --others --exclude-standard -- \
      '*.c' '*.h' ':(exclude)vmlinux.h' | xargs clang-format -i
      mdformat README.md
      nixfmt devenv.nix'';
  };

  # https://devenv.sh/basics/
  enterShell = ''
    echo "Available commands:"
    echo " - build        : Make"
    echo " - clean        : Make clean"
    echo " - lint         : Lint repository"
  '';

  # https://devenv.sh/tests/
  enterTest = ''
    build
    clean
  '';

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    checkmake.enable = true;
    clang-format.enable = true;
    mdformat.enable = true;
    nixfmt-classic.enable = true;
    trim-trailing-whitespace.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
