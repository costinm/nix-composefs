{
  description = "nix-composefs — /nix/store as a signed, syncable composefs store";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, crane, flake-utils }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import rust-overlay) ];
      };

      rustToolchain = pkgs.rust-bin.stable.latest.default;
      craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);
      src = craneLib.cleanCargoSource ./.;

      # Everything the binary needs at build time comes from Nix:
      # - perl + gnumake + cc (stdenv): the composefs crate depends on the
      #   openssl crate for its hashers; it is built vendored (from source)
      #   so the resulting binary has no dynamic libssl dependency.
      nativeBuildInputs = with pkgs; [ gnumake perl ];

      nixComposefs = craneLib.buildPackage {
        inherit src;
        pname = "nix-composefs";
        strictDeps = true;
        doCheck = true;
        inherit nativeBuildInputs;
      };

      # Runtime tooling for the sync/verify workflow (SSH transfer, verity,
      # erofs inspection). Consumed by env.sh via the profile bin/.
      deps = pkgs.symlinkJoin {
        name = "nix-composefs-deps";
        paths = with pkgs; [
          coreutils
          erofs-utils
          findutils
          fsverity-utils
          gnused
          openssh
          rsync
          gnutar
        ];
      };

      devShell = pkgs.mkShell {
        buildInputs = [
          rustToolchain
          nixComposefs
          deps
          pkgs.cargo
        ] ++ nativeBuildInputs;
        shellHook = ''
          export CARGO_TARGET_DIR="$PWD/target/cargo"
        '';
      };
    in
    {
      packages.${system} = {
        default = nixComposefs;
        "nix-composefs" = nixComposefs;
        inherit nixComposefs deps;
      };
      devShells.${system}.default = devShell;
    };
}
