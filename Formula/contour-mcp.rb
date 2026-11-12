class ContourMcp < Formula
  desc "Read-only MCP server exposing Contour to AI agents"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-rc.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-mcp-0.5.0-rc.2-macos-arm64.zip"
      sha256 "d77f33dde3040bf27d74b414d6aa0e88dd2fc73e77398e18006617da2b465fd7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-mcp-0.5.0-rc.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "fa5af164b02c4d508e7ac8a4e713a3c337d5bf3d0e08b308bb4711df3713667d"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-mcp-0.5.0-rc.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "2a42ebcd84598b08c2b458e6d8beb7536dac4ed9a36b28665789663585c0df10"
    end
  end

  def install
    bin.install "contour-mcp"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour-mcp --version")
  end
end
