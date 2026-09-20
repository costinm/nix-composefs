{
  description = "nix-composefs — composefs images and digest stores for Nix closures";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane }:
    let
      system = "x86_64-linux";
      muslTarget = "x86_64-unknown-linux-musl";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import rust-overlay) ];
      };

      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        targets = [ muslTarget ];
      };
      craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);
      src = craneLib.cleanCargoSource ./.;

      # Build for musl like initos does: crane runs on the glibc (host)
      # stdenv, but cargo is pointed at the musl target and the musl gcc from
      # pkgsStatic is put on PATH (as musl-gcc) and set as both the cargo
      # linker and CC for the target triple, so vendored openssl compiles
      # for musl too.
      muslLinker = "${pkgs.pkgsStatic.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
      muslArgs = {
        CARGO_BUILD_TARGET = muslTarget;
        CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = muslLinker;
        CC_x86_64_unknown_linux_musl = muslLinker;
        preBuild = ''
          mkdir -p .bin
          ln -s ${muslLinker} .bin/musl-gcc
          export PATH=$PWD/.bin:$PATH
        '';
      };

      # Everything the binary needs at build time comes from Nix:
      # - perl + gnumake + cc (stdenv): the composefs crate depends on the
      #   openssl crate for its hashers; it is built vendored (from source)
      #   so the resulting binary has no dynamic libssl dependency.
      nativeBuildInputs = with pkgs; [ gnumake perl ];

      nixComposefs = craneLib.buildPackage ({
        inherit src nativeBuildInputs;
        pname = "nix-composefs";
        strictDeps = true;
        doCheck = true;
      } // muslArgs);

      # Runtime tooling used by external transport and InitOS verification.
      deps = pkgs.symlinkJoin {
        name = "nix-composefs-deps";
        paths = with pkgs; [
          coreutils
          erofs-utils
          fsverity-utils
          fuse3
          composefs
        ];
      };

      # Full bundle: our generator plus runtime inspection tools.
      nixComposefsFull = pkgs.symlinkJoin {
        name = "nix-composefs-bundle";
        paths = [ nixComposefs deps ];
      };

      muslCc = pkgs.pkgsStatic.stdenv.cc;

      devShell = pkgs.mkShell {
        buildInputs = [
          rustToolchain
          muslCc
          nixComposefsFull
          pkgs.cargo
        ] ++ nativeBuildInputs;
        shellHook = ''
          export CARGO_TARGET_DIR="$PWD/target/cargo"
          export CARGO_BUILD_TARGET=${muslTarget}
          export CC_x86_64_unknown_linux_musl=${muslCc}/bin/x86_64-unknown-linux-musl-gcc
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=${muslCc}/bin/x86_64-unknown-linux-musl-gcc
        '';
      };
    in
    {
      packages.${system} = {
        default = nixComposefsFull;
        "nix-composefs" = nixComposefsFull;
        "nix-composefs-bin" = nixComposefs;
        inherit nixComposefs deps;
      };
      devShells.${system}.default = devShell;
    };
}
