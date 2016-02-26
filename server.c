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


#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

 int pem_passwd_cb(char *buf, int size, int rwflag, void *password)
 {
  strncpy(buf, (char *)(password), size);
  buf[size - 1] = '\0';
  printf("Called pem_passwd_cb\n");
  return(strlen(buf));
 }

SSL_CTX* InitServerCTX(char* CertFile, char* KeyFile, char *password)
{   
    SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv23_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_load_verify_locations(ctx, CertFile, 0) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_use_certificate_chain_file(ctx, KeyFile) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
    //SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");
    //New lines - Force the client-side have a certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
#if (OPENSSL_VERSION_NUMBER < 0x0090600fL)
    SSL_CTX_set_verify_depth(ctx,1);
#endif
    return ctx;
}

int check_client_cert (SSL *ssl) {
  X509 *peer;
  char peer_CN[256];
  char email_check[256];
  if(SSL_get_verify_result(ssl)!=X509_V_OK) {
    printf (FMT_ACCEPT_ERR);
    printf("Fail client cert check\n");
    return -1;
  }
  /*Check the common name*/
  peer=SSL_get_peer_certificate(ssl);
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_pkcs9_emailAddress, email_check, 256);
  printf(FMT_CLIENT_INFO, peer_CN, email_check);
  return 0;
}

void shutdownSSLserver (SSL* ssl){
    printf("Server SSL shutting down\n");
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

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  char CertFile[] = "568ca.pem";
  char KeyFile[] = "bob.pem";
  SSL_CTX *ctx;
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
  fprintf(stderr,"invalid port number");
  exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  ctx = InitServerCTX(CertFile, KeyFile, "password");

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";
      SSL *ssl;
      ssl = SSL_new(ctx);
      SSL_set_fd(ssl, s);

      if (SSL_accept(ssl) == -1){
        //printf("Here1\n");
        printf (FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
      } else {
        //len = recv(s, &buf, 255, 0);
        //ShowCerts(ssl);
        if (check_client_cert(ssl) != 0) {
          close(sock);
          SSL_CTX_free(ctx);
          return 0;
        }
        len = SSL_read(ssl, &buf, 255);
        switch(SSL_get_error(ssl, len)){
          case SSL_ERROR_NONE:
            break;
          case SSL_ERROR_ZERO_RETURN:
            shutdownSSLserver(ssl);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            return 0;
          case SSL_ERROR_SYSCALL:
          //premature closure message
            printf(FMT_INCOMPLETE_CLOSE);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            return 0;
          default:
            printf ("Server read error\n"); 
        }
        buf[len]= '\0';
        printf(FMT_OUTPUT, buf, answer);
        //send(s, answer, strlen(answer), 0);
        int check = SSL_write (ssl, answer, strlen(answer));
        switch(SSL_get_error(ssl, check)){
          case SSL_ERROR_NONE:
            if (check != strlen(answer))
              printf ("Write Incomplete\n");
            break;
          case SSL_ERROR_ZERO_RETURN:
            break;
          case SSL_ERROR_SYSCALL:
            //premature closure message
            printf(FMT_INCOMPLETE_CLOSE);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            return 0;
          default:
            printf("Server write error\n"); 
        }
        //setup bi-directional shutdown
        int success = SSL_shutdown(ssl);
        if (success == 0) {
          shutdownSSLserver(ssl);
        } else if (success < 0) {
          printf("Server shutdown error\n");
        } else {
          SSL_free(ssl);
        }
      }
      close(sock);
      close(s);
      return 0;
    }
  }
  SSL_CTX_free(ctx);
  close(sock);
  return 1;
}

