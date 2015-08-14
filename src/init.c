#include <R_ext/Rdynload.h>
#include <Rinternals.h>
#include <libssh2.h>
#include <libssh2_sftp.h>

void R_init_ssh(DllInfo *info) {

  /* init winsock */
  #ifdef WIN32
    WSADATA wsadata;
    int err = WSAStartup(MAKEWORD(2,0), &wsadata);
    if (err != 0)
      Rf_error(stderr, "WSAStartup failed with error: %d\n", err);
  #endif

  /* init libssh2 */
  int rc = libssh2_init (0);
  if (rc != 0)
    Rf_error ("libssh2 initialization failed (%d)\n", rc);
}

void R_unload_ssh(DllInfo *info) {
  libssh2_exit();
}
