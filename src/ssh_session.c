/* To do notes:
 *  - When libssh2 is built against gcrypt instead of openssl we need to specify
 *    a pubkey file in libssh2_userauth_publickey_fromfile.
 */

#include <Rinternals.h>
#include <libssh2.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#endif

#include <stdlib.h>

#define log(...) if(verb) Rprintf(__VA_ARGS__)

struct session_data {
  int verbose;
  SEXP passcb;
};

SEXP readpassword(const char *text, SEXP fun){
  if(isString(fun))
    return fun;
  int err;
  SEXP call = PROTECT(LCONS(fun, LCONS(mkString(text), R_NilValue)));
  SEXP res = PROTECT(R_tryEval(call, R_GlobalEnv, &err));
  UNPROTECT(2);
  if(err || !isString(res))
    error("Password callback did not return a string value");
  return res;
}

static void kbd_callback(const char *name, int name_len, const char *instruction,
  int instruction_len, int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
  LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void **abstract) {

  /* get session data */
  struct session_data *data = *abstract;

  if(name_len)
    Rprintf("Authenticating for %s\n", name);

  if(instruction_len)
    Rprintf("Instructions: %s\n", instruction);

  for (int i = 0; i < num_prompts; i++) {
    void *str = malloc(prompts[i].length);
    memcpy(str, prompts[i].text, prompts[i].length);
    prompts[i].text[prompts[i].length] = '\0';
    SEXP res = readpassword(str, data->passcb);
    free(str);
    responses[i].length = LENGTH(STRING_ELT(res, 0));
    responses[i].text = malloc(LENGTH(STRING_ELT(res, 0)));
    memcpy(responses[i].text, CHAR(STRING_ELT(res, 0)), responses[i].length);
  }
}

const char *get_error(LIBSSH2_SESSION *session, const char *str){
  char *buf = malloc(1000);
  char *errmsg = NULL;
  int err = libssh2_session_last_error(session, &errmsg, NULL, 0);
  snprintf(buf, 1000, "ssh %s error %d: %s\n", str, err, errmsg);
  return buf;
}

SEXP R_ssh_session(SEXP host, SEXP port, SEXP user, SEXP key, SEXP password, SEXP verbose){

  /* user-pass */
  int verb = asLogical(verbose);
  const char *username = CHAR(STRING_ELT(user, 0));

  /* Connect to host */
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(asInteger(port));

  /* Resovle hostname */
  struct hostent *hostaddr = gethostbyname(CHAR(STRING_ELT(host, 0)));
  if(!hostaddr)
    Rf_error("Failed to resolve hostname");

  //sin.sin_addr.s_addr = inet_addr(CHAR(STRING_ELT(host, 0)));
  sin.sin_addr.s_addr = *(long*)(hostaddr->h_addr);

  if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0)
    Rf_error("failed to connect to %s:%d!\n", CHAR(STRING_ELT(host, 0)), asInteger(port));

  /* Setup SSL session */
  LIBSSH2_SESSION *session = libssh2_session_init();
  if (libssh2_session_handshake(session, sock))
    get_error(session, "session handshake");

  /* private data */
  struct session_data data;
  void **abstract = libssh2_session_abstract(session);
  data.verbose = asLogical(verbose);
  data.passcb = password;
  *abstract = &data;

  /* Get host sha1 pubkey */
  unsigned char *md5 = (unsigned char*) libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
  char fingerprint[48];
  char *ptr = fingerprint;
  for(int i = 0; i < 16; i++) {
    snprintf(ptr, 4, "%02x:", md5[i]);
    ptr+=3;
  }
  ptr[-1] = '\0';
  log("Host RSA key fingerprint is %s\n", fingerprint);

  /* check what authentication methods are available */
  char *authlist = libssh2_userauth_list(session, username, strlen(username));
  log("userauthlist: %s\n", authlist);

  /* First try public key authentication */
  if (key != R_NilValue && strstr(authlist, "publickey")) {
    const char *keyfile = CHAR(STRING_ELT(key, 0));
    log("Trying public key authentication\n");
    int err = libssh2_userauth_publickey_fromfile(session, username, NULL, keyfile, NULL);
    if(err == -16) {
      //retry with passphrase
      log(get_error(session, "key passphrase"));
      SEXP pw = readpassword("Enter private key passphrase:", password);
      if ((err = libssh2_userauth_publickey_fromfile(session, username, NULL, keyfile, CHAR(STRING_ELT(pw, 0)))))
        log(get_error(session, "private key"));
    }
    if(!err){
      log("Authentication by public key succeeded.\n");
      goto auth_done;
    }
  }

  /* Try keyboard-interactive auth */
  if (strstr(authlist, "keyboard-interactive")) {
    log("Trying keyboard-interactive authentication\n");
    if (libssh2_userauth_keyboard_interactive(session, username, &kbd_callback) ) {
      log(get_error(session, "interactive auth"));
    } else {
      log("Authentication by keyboard-interactive succeeded.\n");
      goto auth_done;
    }
  }

  /* Try fixed password auth */
  if (strstr(authlist, "password")) {
    log("Trying basic password authentication\n");
    SEXP pw = readpassword("Enter password:", password);
    if (libssh2_userauth_password(session, username, CHAR(STRING_ELT(pw, 0)))) {
      log(get_error(session, "password auth"));
    } else {
      log("Authentication by password succeeded.\n");
      goto auth_done;
    }
  }

  Rf_error("Authentication failed");
  auth_done: log("Done with auth\n");

  /* Request a shell */
  LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
  if(!channel)
    Rf_error(get_error(session, "open channel"));

  if (libssh2_channel_request_pty(channel, "vanilla"))
    Rf_error(get_error(session, "request pty"));

  /* Open a shell on that pty */
  if (libssh2_channel_shell(channel))
    Rf_error(get_error(session, "channel shell"));

  size_t max = 1000000;
  char buf[max];
  ssize_t len = libssh2_channel_read(channel, buf, max);
  SEXP out = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, mkCharLen(buf, len));
  UNPROTECT(1);
  return out;
}
