class Libssh2 < Formula
  desc "C library implementing the SSH2 protocol"
  homepage "http://www.libssh2.org/"
  url "http://www.libssh2.org/download/libssh2-1.6.0.tar.gz"
  sha256 "5a202943a34a1d82a1c31f74094f2453c207bf9936093867f41414968c8e8215"

  head do
    url "https://github.com/libssh2/libssh2.git"

    depends_on "autoconf" => :build
    depends_on "automake" => :build
    depends_on "libtool" => :build
  end

  def install
    args = %W[
      --prefix=#{prefix}
      --disable-debug
      --disable-dependency-tracking
      --disable-silent-rules
      --disable-examples-build
      --with-openssl
      --enable-static
      --disable-shared
      --with-libz
    ]

    system "./buildconf" if build.head?
    system "./configure", *args
    system "make", "install"
  end

  test do
    (testpath/"test.c").write <<-EOS.undent
      #include <libssh2.h>

      int main(void)
      {
      libssh2_exit();
      return 0;
      }
    EOS

    system ENV.cc, "test.c", "-L#{lib}", "-lssh2", "-o", "test"
    system "./test"
  end
end
