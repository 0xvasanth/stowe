# Draft Homebrew formula for stowe.
#
# To ship this:
#   1. Create a public GitHub repo named `homebrew-tap` under your account
#      (e.g. https://github.com/0xvasanth/homebrew-tap).
#   2. Copy this file into that repo at `Formula/stowe.rb`.
#   3. Users install with:
#         brew install 0xvasanth/tap/stowe
#
# This formula builds from source via `cargo install`. A signed-binary
# bottle is M6 work (requires Apple Developer ID + notarization).

class Stowe < Formula
  desc "Local-first secrets vault for macOS, backed by the system Keychain"
  homepage "https://github.com/0xvasanth/stowe"
  url "https://github.com/0xvasanth/stowe.git",
      tag:      "m5c",
      revision: "REPLACE_WITH_TAG_SHA"
  license "MIT"
  head "https://github.com/0xvasanth/stowe.git", branch: "main"

  depends_on "rust" => :build
  depends_on "bun" => :build
  depends_on :macos

  def install
    # Build the frontend bundle so Tauri's generate_context!() embeds it.
    cd "crates/stowe/web" do
      system "bun", "install", "--frozen-lockfile"
      system "bun", "run", "build"
    end

    system "cargo", "install", *std_cargo_args(path: "crates/stowe")
  end

  test do
    # Smoke: the binary runs and prints help.
    assert_match "Local-first secrets vault", shell_output("#{bin}/stowe --help")
  end
end
