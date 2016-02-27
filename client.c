#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"                //check
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"                         //check
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"                                 //check
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n" //check
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"    //check
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"        //check
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"              //check


 int pem_passwd_cb(char *buf, int size, int rwflag, void *password)
 {
  strncpy(buf, (char *)(password), size);
  buf[size - 1] = '\0';
  printf("Called pem_passwd_cb\n");
  return(strlen(buf));
 }
 
int check_cert(ssl, host, email)
SSL *ssl;
char *host;
char *email;
{
 X509 *peer;
 char peer_CN[256];
 char email_check[256];
 char issuer[256];
 if(SSL_get_verify_result(ssl)!=X509_V_OK) {
  printf (FMT_NO_VERIFY);
  return -1;
 }
 /*Check the common name*/
 peer=SSL_get_peer_certificate(ssl);
 X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
 if(strcasecmp(peer_CN,host)) {
  printf(FMT_CN_MISMATCH);
  return -1;
 }
 X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_pkcs9_emailAddress, email_check, 256);
 if(strcasecmp(email_check,email)) {
  printf(FMT_EMAIL_MISMATCH);
  return -1;
 }
  X509_NAME_get_text_by_NID (X509_get_issuer_name(peer), NID_commonName, issuer, 256);
  printf(FMT_SERVER_INFO, peer_CN, email_check, issuer);
  return 0;
}

SSL_CTX* Initialize_CTX(char* CertFile, char* KeyFile, char* password)
{   
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL ) {
      ERR_print_errors_fp(stderr);
      abort();
    }
    if ( SSL_CTX_use_certificate_chain_file(ctx, KeyFile) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
    //SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

    if (SSL_CTX_load_verify_locations(ctx, CertFile, 0) != 1)
        ERR_print_errors_fp(stderr);
      
    SSL_CTX_set_verify_depth(ctx,4);
    return ctx;
}

void shutdownSSLclient (SSL* ssl){
    printf("Client SSL shutting down\n");
    int r = SSL_shutdown(ssl);
       
    switch(r){
    //successful shutdown
    case 1:
      break;
    //shutdown not yet finished
    case 0:
      printf("Shutdown incomplete\n");
      break;
    //failed shutdown
    case -1:
      printf("Shutdown error\n");
      break;
    default:
      printf("Shutdown failed\n");       
    }
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  char CertFile[] = "568ca.pem";
  char KeyFile[] = "alice.pem";
  SSL_CTX *ctx;
  SSL *ssl;
  //secret = "TEST TEST TEST 123";
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
  fprintf(stderr,"invalid port number");
  exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }

  SSL_library_init();
  ctx = Initialize_CTX(CertFile, KeyFile, "password");
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_cipher_list(ctx, "SHA1");
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);
  if (SSL_connect(ssl) == -1) {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors_fp(stdout);
  } else {
    if (check_cert(ssl, "Bob's Server", "ece568bob@ecf.utoronto.ca") != 0) {
      close (sock);
      SSL_CTX_free(ctx);
      return 0;
    }
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    //ShowCerts(ssl);
    int check = SSL_write(ssl, secret, strlen(secret));
    switch(SSL_get_error(ssl, check)){
      case SSL_ERROR_NONE:
        if(check!=strlen(secret))
          printf("write not complete\n");
        break;
      case SSL_ERROR_ZERO_RETURN:
        shutdownSSLclient (ssl);
        SSL_free(ssl);
        close (sock);
        SSL_CTX_free(ctx);
        return 0;
      case SSL_ERROR_SYSCALL:
        //premature closure message
        printf(FMT_INCORRECT_CLOSE);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 0;
      default:
        printf ("Client write error\n");     
    }


    len = SSL_read(ssl, buf, 255);
    while (len > 0) {
      buf[len]='\0';
      printf(FMT_OUTPUT, secret, buf);
      len = SSL_read(ssl, buf, 255);
    }
    switch(SSL_get_error(ssl, len)){
      case SSL_ERROR_NONE:
        break;
      case SSL_ERROR_ZERO_RETURN:
        break;
      case SSL_ERROR_SYSCALL:
        //premature closure message
        printf(FMT_INCORRECT_CLOSE);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 0;
      default:
        printf ("Client read error\n");
    }
    
    shutdownSSLclient (ssl);
    SSL_free(ssl);
  }
  close(sock);
  SSL_CTX_free(ctx);
  return 1;
}

