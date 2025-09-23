{ pkgs, ... }:

{
  # https://devenv.sh/packages/
  packages = with pkgs; [
    git
    clangStdenv
    elfutils
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

  # https://devenv.sh/tasks/
  tasks = {
    "lint:run".exec = ''
      checkmake src/Makefile
      git ls-files --cached --others --exclude-standard '*.c' '*.h' | xargs clang-format -i
      mdformat README.md
      nixfmt devenv.nix'';
  };

  enterTest = ''
    make
    make clean
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
