class ContourMcp < Formula
  desc "Read-only MCP server exposing Contour to AI agents"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-beta.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-beta.2/contour-mcp-0.5.0-beta.2-macos-arm64.zip"
      sha256 "223e5703b3f88c46c20a8f37e1fcab06930a488e0eb850f2ee371109a23046e1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-beta.2/contour-mcp-0.5.0-beta.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "44cf44a51f5585b0a7c69f02780f28d5a79b1fafccf5479bc6ff0a05b81c79cc"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-beta.2/contour-mcp-0.5.0-beta.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "11eaa83d4503d19790093ebec0bc0f1cedcfade5fff182e5ff486b159089091e"
    end
  end

  def install
    bin.install "contour-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour-mcp --version")
  end
end
