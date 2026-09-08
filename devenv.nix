{ pkgs, ... }:

{
  # https://devenv.sh/packages/
  packages = with pkgs; [
    git
  ];

  # https://devenv.sh/languages/
  languages.rust = {
    enable = true;
    channel = "stable";
    components = [
      "rustc"
      "cargo"
      "clippy"
      "rustfmt"
      "rust-analyzer"
    ];
    targets = [ "x86_64-unknown-linux-gnu" ];
  };

  # https://devenv.sh/tests/
  enterTest = ''
    cargo -V
  '';

  # https://devenv.sh/git-hooks/
  git-hooks.hooks = {
    cargo-check.enable = true;
    clippy.enable = true;
    mdformat.enable = true;
    nixfmt.enable = true;
    rustfmt.enable = true;
    trim-trailing-whitespace.enable = true;
  };

  # See full reference at https://devenv.sh/reference/options/
}
