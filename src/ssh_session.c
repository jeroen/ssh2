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
#include <unistd.h>
#include <netdb.h>
#endif

#include <stdlib.h>

#define log(...) if(verb) Rprintf(__VA_ARGS__); Rprintf("\n")

typedef struct {
  int sock;
  int verbose;
  SEXP passcb;
  LIBSSH2_CHANNEL *channel;
} session_data;

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
  //struct session_data *data = *abstract;
  session_data* data = (session_data*) *abstract;

  if(name_len)
    Rprintf("Authenticating for %s\n", name);

  if(instruction_len)
    Rprintf("Instructions: %s\n", instruction);

  for (int i = 0; i < num_prompts; i++) {
    char *str = malloc(prompts[i].length+1);
    memcpy(str, prompts[i].text, prompts[i].length);
    str[prompts[i].length] = '\0';
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
  snprintf(buf, 1000, "ssh %s error %d: %s", str, err, errmsg);
  return buf;
}

void cleanup_session(LIBSSH2_SESSION *session){
  void **abstract = libssh2_session_abstract(session);
  session_data* data = (session_data*) *abstract;
  int verb = data->verbose;
  int sock = data->sock;
  log("Cleaning up session");
  if(libssh2_session_disconnect(session, "See you later"))
    log(get_error(session, "session disconnect"));
  if(libssh2_session_free(session))
    log(get_error(session, "session free"));
  #ifdef WIN32
    closesocket(sock);
  #else
    close(sock);
  #endif
}

void ssh_error(LIBSSH2_SESSION *session, const char *str){
  const char *errstr = get_error(session, str);
  Rf_error(errstr);
}

void fin_session(SEXP ptr){
  LIBSSH2_SESSION *session = (LIBSSH2_SESSION*) R_ExternalPtrAddr(ptr);
  if(session)
    cleanup_session(session);
  R_ClearExternalPtr(ptr);
}

SEXP R_ssh_session(SEXP host, SEXP port, SEXP user, SEXP key, SEXP password, SEXP verbose){

  /* user-pass */
  int verb = asLogical(verbose);
  const char *username = CHAR(STRING_ELT(user, 0));

  /* Resovle hostname */
  struct hostent *hostaddr = gethostbyname(CHAR(STRING_ELT(host, 0)));
  if(!hostaddr)
    Rf_error("Failed to resolve hostname");

  /* allocate socket */
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(asInteger(port));
  sin.sin_addr.s_addr = *(long*)(hostaddr->h_addr);

  /* allocate ssh session */
  LIBSSH2_SESSION *session = libssh2_session_init();
  session_data *data = malloc(sizeof(session_data));
  data->verbose = asLogical(verbose);
  data->passcb = password;
  data->sock = sock;

  /* store session data in session abstract */
  void **abstract = libssh2_session_abstract(session);
  *abstract = data;

  /* Connect to host */
  log("starting handshake");
  if (connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0)
    Rf_error("failed to connect to %s:%d!", CHAR(STRING_ELT(host, 0)), asInteger(port));
  if (libssh2_session_handshake(session, sock))
    ssh_error(session, "session handshake");

  /* Get host sha1 pubkey */
  unsigned char *md5 = (unsigned char*) libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
  char fingerprint[48];
  char *cursor = fingerprint;
  for(int i = 0; i < 16; i++) {
    snprintf(cursor, 4, "%02x:", md5[i]);
    cursor+=3;
  }
  cursor[-1] = '\0';
  log("Host RSA key fingerprint is %s", fingerprint);

  /* check what authentication methods are available */
  char *authlist = libssh2_userauth_list(session, username, strlen(username));
  log("userauthlist: %s", authlist);

  /* First try public key authentication */
  if (key != R_NilValue && strstr(authlist, "publickey")) {
    const char *keyfile = CHAR(STRING_ELT(key, 0));
    log("Trying public key authentication");
    int err = libssh2_userauth_publickey_fromfile(session, username, NULL, keyfile, NULL);
    if(err == -16) {
      //retry with passphrase
      log(get_error(session, "key passphrase"));
      SEXP pw = readpassword("Enter private key passphrase:", password);
      if ((err = libssh2_userauth_publickey_fromfile(session, username, NULL, keyfile, CHAR(STRING_ELT(pw, 0)))))
        log(get_error(session, "private key"));
    }
    if(!err){
      log("Authentication by public key succeeded.");
      goto auth_done;
    }
  }

  /* Try keyboard-interactive auth */
  if (strstr(authlist, "keyboard-interactive")) {
    log("Trying keyboard-interactive authentication");
    if (libssh2_userauth_keyboard_interactive(session, username, &kbd_callback) ) {
      log(get_error(session, "interactive auth"));
    } else {
      log("Authentication by keyboard-interactive succeeded.");
      goto auth_done;
    }
  }

  /* Try fixed password auth */
  if (strstr(authlist, "password")) {
    log("Trying basic password authentication");
    SEXP pw = readpassword("Enter password:", password);
    if (libssh2_userauth_password(session, username, CHAR(STRING_ELT(pw, 0)))) {
      log(get_error(session, "password auth"));
    } else {
      log("Authentication by password succeeded.");
      goto auth_done;
    }
  }

  cleanup_session(session);
  Rf_error("Authentication failed");

  auth_done: log("Opening channel");

  /* Request a shell */
  LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
  if(!channel)
    ssh_error(session, "open channel");

  if (libssh2_channel_request_pty(channel, "vanilla"))
    ssh_error(session, "request pty");

  /* Open a shell on that pty */
  if (libssh2_channel_shell(channel))
    ssh_error(session, "channel shell");

  data->channel = channel;

  /* Return pointer */
  SEXP ptr = PROTECT(R_MakeExternalPtr(session, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(ptr, fin_session, 1);
  setAttrib(ptr, R_ClassSymbol, mkString("ssh_session"));
  UNPROTECT(1);
  return ptr;
}

LIBSSH2_SESSION *get_session(SEXP ptr){
  if(!R_ExternalPtrAddr(ptr))
    error("session is dead");
  LIBSSH2_SESSION *session = (LIBSSH2_SESSION*) R_ExternalPtrAddr(ptr);
  return session;
}

LIBSSH2_CHANNEL *get_channel(LIBSSH2_SESSION *session){
  void **abstract = libssh2_session_abstract(session);
  session_data* data = (session_data*) *abstract;
  return data->channel;
}

SEXP R_channel_read(SEXP ptr, SEXP read_stderr){
  int max = 100000;
  LIBSSH2_SESSION *session = get_session(ptr);
  void **abstract = libssh2_session_abstract(session);
  session_data* data = (session_data*) *abstract;
  int verb = data->verbose;
  char buf[max];
  log("reading channel");

  libssh2_session_set_blocking(session, 0);
  ssize_t len;
  if(asLogical(read_stderr)){
    len = libssh2_channel_read_stderr(data->channel, buf, max);
  } else {
    len = libssh2_channel_read(data->channel, buf, max);
  }
  libssh2_session_set_blocking(session, 1);

  if(len == LIBSSH2_ERROR_EAGAIN)
    return R_NilValue;

  if(len < 0){
    ssh_error(session, "channel read");
  } else {
    log("found %d bytes", len);
  }

  SEXP res = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(res, 0, mkCharLenCE(buf, len, CE_UTF8));
  UNPROTECT(1);
  return res;
}

SEXP R_channel_write(SEXP ptr, SEXP x, SEXP write_stderr){
  LIBSSH2_SESSION *session = get_session(ptr);
  void **abstract = libssh2_session_abstract(session);
  session_data* data = (session_data*) *abstract;
  int verb = data->verbose;
  ssize_t len;
  for(int i = 0; i < LENGTH(x); i++){
    SEXP string = STRING_ELT(x, i);
    if(asLogical(write_stderr)){
      len = libssh2_channel_write_stderr(data->channel, CHAR(string), LENGTH(string));
    } else {
      len = libssh2_channel_write(data->channel, CHAR(string), LENGTH(string));
    }
    if(len < 0){
      ssh_error(session, "channel read");
    } else {
      log("wrote %d bytes", len);
    }
  }
  return R_NilValue;
}
