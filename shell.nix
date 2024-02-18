with import <nixpkgs> {};

mkShell {
    buildInputs = [
      nodejs_18
      helix
      gleam
      erlang
      rebar3
      cheat
      bat
      nil
      nodePackages.typescript-language-server
    ];
  }

