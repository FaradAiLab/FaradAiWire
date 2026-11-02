class Faradaiwire < Formula
  desc "Zero-trust security gateway for AI agents & MCP"
  homepage "https://github.com/FaradAiLab/FaradAiWire"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/FaradAiLab/FaradAiWire/releases/download/v#{version}/faradaiwire_#{version}_darwin_arm64.tar.gz"
      # sha256 "REPLACE_WITH_SHA256_FROM_CHECKSUMS_TXT"
    else
      url "https://github.com/FaradAiLab/FaradAiWire/releases/download/v#{version}/faradaiwire_#{version}_darwin_amd64.tar.gz"
      # sha256 "REPLACE_WITH_SHA256_FROM_CHECKSUMS_TXT"
    end
  end

  on_linux do
    url "https://github.com/FaradAiLab/FaradAiWire/releases/download/v#{version}/faradaiwire_#{version}_linux_amd64.tar.gz"
    # sha256 "REPLACE_WITH_SHA256_FROM_CHECKSUMS_TXT"
  end

  def install
    bin.install "faradaiwire"
  end

  # macOS Background Daemon Service (launchd)
  service do
    run [opt_bin/"faradaiwire"]
    keep_alive true
    log_path var/"log/faradaiwire.log"
    error_log_path var/"log/faradaiwire.error.log"
    working_dir var
  end

  test do
    system "#{bin}/faradaiwire", "--help"
  end
end
