# Build against static libraries from curl website.
if(!file.exists("../windows/libssh2-1.6.0/include/libssh2.h")){
  if(getRversion() < "3.3.0") setInternet2()
  download.file("https://github.com/rwinlib/libssh2/archive/v1.6.0.zip", "lib.zip", quiet = TRUE)
  dir.create("../windows", showWarnings = FALSE)
  unzip("lib.zip", exdir = "../windows")
  unlink("lib.zip")
}
