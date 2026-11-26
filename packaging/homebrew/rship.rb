class Rship < Formula
  desc "Cross-platform, low-memory, crash-resumable multi-cloud transfer and sync engine"
  homepage "https://hua0512.github.io/rship/"
  version "0.1.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/hua0512/rship/releases/download/v#{version}/rship-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AARCH64_DARWIN"
    else
      url "https://github.com/hua0512/rship/releases/download/v#{version}/rship-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_X86_64_DARWIN"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/hua0512/rship/releases/download/v#{version}/rship-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AARCH64_LINUX_GNU"
    else
      url "https://github.com/hua0512/rship/releases/download/v#{version}/rship-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_X86_64_LINUX_GNU"
    end
  end

  def install
    bin.install "rship"
    generate_completions_from_executable(bin/"rship", "completions")
  end

  test do
    assert_match "rship", shell_output("#{bin}/rship --version")
  end
end
