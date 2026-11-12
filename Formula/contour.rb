class Contour < Formula
  desc "Device management configuration toolkit for Apple MDM, Fleet GitOps, and mSCP"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-rc.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-0.5.0-rc.2-macos-arm64.zip"
      sha256 "883eb26321cdc8e19799de68bda44a38bbb5c6562d92d206548fc88b8aab563e"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-0.5.0-rc.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c48767d3acfdf12b627884b50d6e36a71ae963b8a9c7bed545838c516689feff"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-0.5.0-rc.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "49529efb942c7313ddb0589af8d6b310a340555bd9c20faa93bc1bcab014d1fa"
    end
  end

  def install
    bin.install "contour"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour --version")
  end
end
