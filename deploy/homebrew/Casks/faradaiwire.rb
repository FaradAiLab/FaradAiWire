cask "faradaiwire" do
  arch arm: "darwin_arm64", intel: "darwin_amd64"

  version "1.0.0"
  sha256 arm:   "c47dafcc766795b1f68676fb9fe0c653137d9b4e6f40927f2d842f5de9f4d6c1",
         intel: "2c8ee50bc3d4aff2ba9b13a0f40b1034da692d4ea70e94bc63e4d1c7d579ee5b"

  url "https://github.com/FaradAiLab/FaradAiWire/releases/download/v#{version}/faradaiwire_#{version}_#{arch}.tar.gz"
  name "FaradAiWire"
  desc "Zero-trust security gateway for AI agents & MCP"
  homepage "https://github.com/FaradAiLab/FaradAiWire"

  depends_on macos: :monterey

  binary "faradaiwire"

  zap trash: "~/.faradaiwire"
end
