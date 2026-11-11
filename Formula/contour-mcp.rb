class ContourMcp < Formula
  desc "Read-only MCP server exposing Contour to AI agents"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-rc.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.1/contour-mcp-0.5.0-rc.1-macos-arm64.zip"
      sha256 "d2399187d22f588cac5205f1d0f84f7e7e7390030d396884e3123fd5614da382"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.1/contour-mcp-0.5.0-rc.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8ceef4b13b8676a6d00cc7745ae15d69a7865780dc95a037d50d4e1b43be382c"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.1/contour-mcp-0.5.0-rc.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3e1259dcb082764134e1c5d61ed33bc762c2f869e68681d82e1b3b6407ec9356"
    end
  end

  def install
    bin.install "contour-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour-mcp --version")
  end
end
