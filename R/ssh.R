#' Secure Shell
#'
#' Start an interactive SSH session.
#'
#' @export
#' @param host string with hostname
#' @param port integer
#' @param user username to authenticate with
#' @param key (optional) private RSA key to authenticate
#' @param password string or callback function with password
#' @param verbose emit some more output
#' @name ssh
#' @rdname ssh
ssh <- function(host, port = 22, user = me(), key = "~/.ssh/id_rsa", password = readline, verbose = FALSE) {
  session <- ssh_session(host, port, user, key, password, verbose)
  channel_attach(session)
  on.exit(channel_detach(session))
  repeat {
    channel_write(session, paste0(readline(" "), "\n"))
    if(channel_eof(session))
      break;
  }
}

#' @useDynLib ssh R_ssh_session
ssh_session <- function(host, port = 22, user = me(), key = "~/.ssh/id_rsa", password = readline, verbose = FALSE){
  stopifnot(is.character(host))
  stopifnot(is.numeric(port))
  stopifnot(is.character(user))
  stopifnot(is.character(password) || is.function(password))
  stopifnot(is.logical(verbose))

  key <- normalizePath(key, mustWork = FALSE)
  if(file.exists(key)){
    if(verbose)
      sprintf("Found key: %s", key)
  } else {
    key <- NULL
    if(verbose)
      sprintf("Key not found: %s", key)
  }
  .Call(R_ssh_session, host, port, user, key, password, verbose)
}

#' @useDynLib ssh R_channel_attach
channel_attach <- function(session){
  .Call(R_channel_attach, session);
}

#' @useDynLib ssh R_channel_detach
channel_detach <- function(session){
  .Call(R_channel_detach, session);
}


#' @useDynLib ssh R_channel_read
channel_read <- function(session){
  .Call(R_channel_read, session, FALSE);
}

#' @useDynLib ssh R_channel_read
channel_read_stderr <- function(session){
  .Call(R_channel_read, session, TRUE);
}

#' @useDynLib ssh R_channel_write
channel_write <- function(session, x){
  stopifnot(is.character(x))
  .Call(R_channel_write, session, x, FALSE);
}

#' @useDynLib ssh R_channel_write
channel_write_stderr <- function(session, x){
  stopifnot(is.character(x))
  .Call(R_channel_write, session, x, TRUE);
}

#' @useDynLib ssh R_channel_eof
channel_eof <- function(session){
  .Call(R_channel_eof, session);
}

me <- function(){
  Sys.info()[["user"]]
}

# Other session methods:
# session <- ssh("myfiles.stat.ucla.")
# session$file(path, "rb")
# session$connection()
# session$console()


scp <- function(path, mode = "r", ...) {
  session <- ssh_session(...)
  session$file(path, mode)
}