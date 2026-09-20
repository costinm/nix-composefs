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
    composefs-rs = {
      url = "github:containers/composefs-rs/v0.9.2";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, rust-overlay, crane, flake-utils, composefs-rs }:
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

      # Upstream cfsctl (composefs mkfs/mount/pull etc.), built from the same
      # composefs-rs sources the crate dependency comes from. Upstream ships
      # no Cargo.lock, so a generated one (deduplicated crates.io
      # resolution) is committed at tools/composefs-rs-Cargo.lock and copied
      # into the source tree before vendoring.
      composefsRsWithLock = pkgs.runCommand "composefs-rs-src-with-lock" { } ''
        cp -r ${composefs-rs} $out
        chmod -R u+w $out
        cp ${./tools/composefs-rs-Cargo.lock} $out/Cargo.lock
      '';

      composefsCfsctl = craneLib.buildPackage ({
        pname = "cfsctl";
        version = "0.9.2";
        src = composefsRsWithLock;
        strictDeps = true;
        doCheck = false;
        cargoExtraArgs = "--bin cfsctl";
        cargoVendorDir = craneLib.vendorCargoDeps { src = composefsRsWithLock; };
        nativeBuildInputs = nativeBuildInputs;
        # cfsctl's openssl-sys is not built vendored upstream; link against
        # the musl (pkgsStatic) OpenSSL so the result stays static.
        OPENSSL_LIB_DIR = "${pkgs.pkgsStatic.openssl.out}/lib";
        OPENSSL_INCLUDE_DIR = "${pkgs.pkgsStatic.openssl.dev}/include";
        OPENSSL_STATIC = "true";
      } // muslArgs);

      # Runtime tooling for the sync/verify workflow (SSH transfer, verity,
      # erofs inspection). fuse3 provides fusermount3, needed by cfsctl's
      # FUSE mount. Consumed by env.sh via the profile bin/.
      deps = pkgs.symlinkJoin {
        name = "nix-composefs-deps";
        paths = with pkgs; [
          coreutils
          erofs-utils
          findutils
          fsverity-utils
          fuse3
          gnused
          openssh
          rsync
          gnutar
        ];
      };

      # Full bundle: our binary + upstream cfsctl + runtime tools.
      nixComposefsFull = pkgs.symlinkJoin {
        name = "nix-composefs-bundle";
        paths = [ nixComposefs composefsCfsctl deps ];
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
        cfsctl = composefsCfsctl;
        inherit nixComposefs deps;
      };
      devShells.${system}.default = devShell;
    };
}
