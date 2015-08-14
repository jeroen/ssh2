#' @export
#' @useDynLib ssh R_ssh_session
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
