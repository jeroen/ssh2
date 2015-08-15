#' SSH
#'
#' Interact with secure shell.
#'
#' @export
#' @useDynLib ssh R_ssh_session
#' @param host string with hostname
#' @param port integer
#' @param user username to authenticate with
#' @param key (optional) private RSA key to authenticate
#' @param password string or callback function with password
#' @param verbose emit some more output
#' @name ssh
#' @rdname ssh
ssh_session <- function(host, port = 22, user = me(), key = "~/.ssh/id_rsa", password = readline, verbose = TRUE){
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

#' @export
#' @useDynLib ssh R_channel_read
#' @rdname ssh
channel_read <- function(session){
  .Call(R_channel_read, session, FALSE);
}

#' @export
#' @useDynLib ssh R_channel_read
#' @rdname ssh
channel_read_stderr <- function(session){
  .Call(R_channel_read, session, TRUE);
}

#' @export
#' @useDynLib ssh R_channel_write
#' @rdname ssh
channel_write <- function(session, x){
  stopifnot(is.character(x))
  .Call(R_channel_write, session, x, FALSE);
}

#' @export
#' @useDynLib ssh R_channel_write
#' @rdname ssh
channel_write_stderr <- function(session, x){
  stopifnot(is.character(x))
  .Call(R_channel_write, session, x, TRUE);
}

ssh <- function(host, port = 22, user = me(), key = "~/.ssh/id_rsa", pubkey =  "~/.ssh/id_rsa.pub", password = readline, verbose = FALSE) {
  session <- ssh_session(host, port, key, password, verbose)
  session$console()
}

scp <- function(path, mode = "r", ...) {
  session <- ssh_session(...)
  session$file(path, mode)
}

me <- function(){
  Sys.info()[["user"]]
}

# Other session methods:
# session <- ssh("myfiles.stat.ucla.")
# session$file(path, "rb")
# session$connection()
# session$console()
