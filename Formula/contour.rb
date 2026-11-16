class Contour < Formula
  desc "Device management configuration toolkit for Apple MDM, Fleet GitOps, and mSCP"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0/contour-0.5.0-macos-arm64.zip"
      sha256 "5bdf5c0b5a553c053d821e6d2fbe10cc951366063a2203f1e59915583ce2cab7"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0/contour-0.5.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "26922075ae3d9df5a31a3e05308142169c9084e7be45884605c96b19acd600eb"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0/contour-0.5.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c2fb480a735027fa9126c83783c9e3d22cfb8f83d301af986c3ff0f936bb00e9"
    end
  end

  def install
    bin.install "contour"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour --version")
  end
end
