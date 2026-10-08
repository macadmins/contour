class Contour < Formula
  desc "Device management configuration toolkit for Apple MDM, Fleet GitOps, and mSCP"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-beta.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-beta.2/contour-0.5.0-beta.2-macos-arm64.zip"
      sha256 "f6aa83531d11336bc726cb617b1c225dd65d699da696cc92c75ded9b6155e915"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-beta.2/contour-0.5.0-beta.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "9de5d417a669163450103e00b9450c1e6e7539cf4ae326917afca874b5a22b17"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-beta.2/contour-0.5.0-beta.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "5873e14496956a37ba36ca63400bb5822e73cb0e5f22014327e0d11bb58f81aa"
    end
  end

  def install
    bin.install "contour"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour --version")
  end
end
