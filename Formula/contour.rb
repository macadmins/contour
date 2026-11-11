class Contour < Formula
  desc "Device management configuration toolkit for Apple MDM, Fleet GitOps, and mSCP"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-rc.1"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.1/contour-0.5.0-rc.1-macos-arm64.zip"
      sha256 "194d81e9597f74d201e74e074e59eeb67a585ab9de2ea6dd838082afcd76136c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.1/contour-0.5.0-rc.1-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "dc61d26050c2cf9d400ea72cea58d8584024a59f594d95567c311a1789896e82"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.1/contour-0.5.0-rc.1-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "d11e5f0fcc8f2225892b4920f6790f77994ee30f9e7b867205f3feabe0a197d1"
    end
  end

  def install
    bin.install "contour"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour --version")
  end
end
