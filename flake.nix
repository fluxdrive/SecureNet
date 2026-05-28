{
  description = "SecureNet — hardware-rooted secure microservice system";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-24.11";
    crane.url       = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";

    # Rust toolchain pinned via rust-overlay for reproducibility
    rust-overlay = {
      url    = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # ── Nixpkgs with rust-overlay applied ──────────────────────────────────
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # ── Rust toolchain ─────────────────────────────────────────────────────
        # Pin to stable. Change the date to update.
        rustToolchain = pkgs.rust-bin.stable."1.78.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" ];
        };

        # ── crane configured with our pinned toolchain ─────────────────────────
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # ── Common build inputs needed by C dependencies ───────────────────────
        # openssl is required by reqwest, rcgen, and rustls native roots.
        nativeBuildInputs = with pkgs; [
          pkg-config
        ];

        buildInputs = with pkgs; [
          openssl
        ];

        # ── Source filtering ───────────────────────────────────────────────────
        # Only include Rust source files and Cargo manifests.
        # Excludes: bootstrap certs, logs, scripts, docs.
        # This keeps the source hash stable when non-Rust files change.
        src = craneLib.cleanCargoSource ./.;

        # ── Common args shared by ALL crate builds ─────────────────────────────
        # crane builds in two stages:
        #   1. cargoArtifacts — compile all dependencies (cached aggressively)
        #   2. per-crate build — compile only the crate's own source
        #
        # Stage 1 is only re-run when Cargo.lock changes.
        # Stage 2 re-runs when the crate's source changes.
        commonArgs = {
          inherit src nativeBuildInputs buildInputs;

          # Tell openssl-sys where to find OpenSSL
          OPENSSL_NO_VENDOR = 1;
          PKG_CONFIG_PATH   = "${pkgs.openssl.dev}/lib/pkgconfig";
        };

        # ── Stage 1: build all workspace dependencies ──────────────────────────
        # This is the expensive step. crane caches it in the Nix store.
        # As long as Cargo.lock doesn't change, this never rebuilds.
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # ── Helper: build a single workspace binary ────────────────────────────
        mkService = { name, extraArgs ? {} }:
          craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            pname         = name;
            cargoExtraArgs = "-p ${name}";
          } // extraArgs);

        # ── Per-service packages ───────────────────────────────────────────────
        vault-service  = mkService { name = "vault-service"; };
        api-gateway    = mkService { name = "api-gateway"; };
        user-service   = mkService { name = "user-service"; };
        order-service  = mkService { name = "order-service"; };

      in {
        # ── Packages ───────────────────────────────────────────────────────────
        # nix build .#vault-service
        # nix build .#api-gateway
        # nix build .#user-service
        # nix build .#order-service
        # nix build          (builds default = all services)
        packages = {
          inherit vault-service api-gateway user-service order-service;

          # Default package builds everything
          default = pkgs.symlinkJoin {
            name  = "securenet";
            paths = [ vault-service api-gateway user-service order-service ];
          };
        };

        # ── Dev shell ──────────────────────────────────────────────────────────
        # nix develop
        # Gives you: cargo, rustc, rust-analyzer, openssl, swtpm, tpm2-tools,
        #            openssl CLI, kubectl, docker, jq
        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            # Rust toolchain (already provided by craneLib.devShell)

            # Build deps
            pkg-config
            openssl
            openssl.dev

            # TPM simulation
            swtpm
            tpm2-tools

            # Observability
            # Jaeger runs as a container; no package needed

            # Ops tooling
            kubectl
            docker
            docker-compose
            jq
            curl

            # Dev quality of life
            cargo-watch   # cargo watch -x run
            cargo-audit   # audit dependencies for known CVEs
            cargo-deny    # enforce license and dependency policies
          ];

          # Environment variables for the dev shell
          shellHook = ''
            echo ""
            echo "  SecureNet dev environment"
            echo "  ─────────────────────────"
            echo "  cargo build --workspace    build all services"
            echo "  cargo test  --workspace    run all tests"
            echo "  cargo audit                check for CVEs"
            echo "  nix build .#vault-service  build vault binary"
            echo "  nix build                  build all binaries"
            echo ""
            export OPENSSL_NO_VENDOR=1
            export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig"
          '';
        };

        # ── Checks ─────────────────────────────────────────────────────────────
        # nix flake check
        # Runs: cargo test, cargo clippy, cargo fmt check
        checks = {
          # Clippy — enforce lint rules
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--workspace -- -D warnings";
          });

          # Formatting check
          fmt = craneLib.cargoFmt { inherit src; };

          # Tests
          test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });
        };
      }
    );
}
