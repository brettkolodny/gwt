with import <nixpkgs> {};

mkShell {
    buildInputs = [
      nodejs_18
      helix
      gleam
      erlang_27
      rebar3
      cheat
      bat
      nil
      nodePackages.typescript-language-server
    ];
  }

