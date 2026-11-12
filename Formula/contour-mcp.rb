class ContourMcp < Formula
  desc "Read-only MCP server exposing Contour to AI agents"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-rc.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-mcp-0.5.0-rc.2-macos-arm64.zip"
      sha256 "359c916c494aafc4a70dbd27db26982cbfb2f2472041e2973168772e0e3bec3e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-mcp-0.5.0-rc.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "bb71ee93b592e626b4f2cc30eed58d09674628a1e65052b366b05ae0dc6da2bf"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-mcp-0.5.0-rc.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4b3e96ca246e45564c33b7f88b85d61bff4f3372c543f19ca2c2f4604022f885"
    end
  end

  def install
    bin.install "contour-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour-mcp --version")
  end
end
