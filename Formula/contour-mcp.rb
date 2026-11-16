class ContourMcp < Formula
  desc "Read-only MCP server exposing Contour to AI agents"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0/contour-mcp-0.5.0-macos-arm64.zip"
      sha256 "53dd10f1229920c312bd7890f14dc7548730eb164990b37dcfa3c17daa6c2d54"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0/contour-mcp-0.5.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "969e9caf5e0ac2fe948f4c1c2c4cc483979dfd6fe157f71f61923fe1c12c76c2"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0/contour-mcp-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "f0410fa75cf07aa2a13058524c4eb4226e2f1b743ac247100b8a855d4e7582b6"
    end
  end

  def install
    bin.install "contour-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour-mcp --version")
  end
end
