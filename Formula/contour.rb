class Contour < Formula
  desc "Device management configuration toolkit for Apple MDM, Fleet GitOps, and mSCP"
  homepage "https://github.com/macadmins/contour"
  version "0.5.0-rc.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-0.5.0-rc.2-macos-arm64.zip"
      sha256 "111940ed29bf5de6be5c0a44caddc6646bb0fe493661c50d99492d27377b3a1a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-0.5.0-rc.2-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "624bbb13597f850c450637123d2007755e3ac9a7f2c58cbe973bd4bf831aab4c"
    end
    on_intel do
      url "https://github.com/macadmins/contour/releases/download/v0.5.0-rc.2/contour-0.5.0-rc.2-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "81ddfe1de2d6e9129a5ac8bd444315bec49f92ec41b39a30d2cfad072935bd8d"
    end
  end

  def install
    bin.install "contour"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/contour --version")
  end
end
