class Roe < Formula
  desc "A disassembler fit for humans"
  homepage "https://github.com/USER/roe"
  url "https://github.com/USER/roe/archive/refs/tags/v1.0.0.tar.gz"
  # Checksum is filled in at release time.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  depends_on "cmake" => :build
  depends_on "pkg-config" => :build
  depends_on "capstone"

  def install
    system "cmake", "-S", ".", "-B", "build", "-DROE_BUILD_TESTS=OFF", *std_cmake_args
    system "cmake", "--build", "build"
    system "cmake", "--install", "build"
  end

  test do
    system "#{bin}/roe", "--version"
  end
end
