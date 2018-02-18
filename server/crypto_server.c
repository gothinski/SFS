/**************************************************************************
 * Crypto_Server.c                                                        *
 *                                                                        *
 * (C) 2017 Gothinski                                                     *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ip.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <signal.h>

#include <memory.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOME "./"
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 77777

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

  unsigned char Key[16],IV[16];
  int sd;
  SSL_CTX* ctx;
  SSL*     ssl;

  char choice[32];
  char choice1[32];
int debug;
char *progname;


/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}


/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}



/**************************************************************************
 * HASH                                                                   *
 **************************************************************************/

void Hash(unsigned char *Key,unsigned char *buffer,int length,char *hash)
{
	HMAC_CTX mdctx;
	unsigned char outhash[32];
	int md_len;
	int l=strlen(Key);
	HMAC_CTX_init(&mdctx);
	HMAC_Init_ex(&mdctx,Key,l,EVP_sha256(),NULL);
	HMAC_Update(&mdctx,buffer,length);
	HMAC_Final(&mdctx,outhash,&md_len);
	HMAC_CTX_cleanup(&mdctx);
	memcpy(hash,outhash,32);
}


/**************************************************************************
 * CHECKING HASH VALUE                                                    *
 **************************************************************************/

int checkhash(unsigned char *Key,unsigned char *buffer,int *length)
{
	char hash1[32],hash2[32],inbuff[BUFSIZE];
	int inputlen = *length;
	inputlen-=32;
	memcpy(inbuff,buffer,inputlen);
	memcpy(hash1,buffer+inputlen,32);
	Hash(Key,buffer,inputlen,hash2);
	*length = inputlen;
	return strncmp(hash1,hash2,32);
}

char* convert_hex(unsigned char *hash,int md_len)
{
	char *hash_hex=(char*)malloc(2*md_len + 1);
	char *hex_buff = hash_hex;
	int i=0;
	for(i=0;i<md_len;i++)
		hex_buff+=sprintf(hex_buff,"%02x",hash[i]);
	*(hex_buff+1)='\0';
	return hash_hex;
}

/**************************************************************************
 * KEY GEN and IV GEN                                                     *
 **************************************************************************/

void gen_key(unsigned char *key)
{
  int i;
  srand(time(NULL));
  for(i=0;i<16;i++)
    key[i]=65+(rand()%26);
}

void gen_iv(unsigned char *iv)
{
  int i;
  srand(time(NULL));
  for(i=0;i<16;i++)
    iv[i]=48+(rand()%10);
}

/**************************************************************************
 * OTP                                                                    *
 **************************************************************************/

int genOTP(char email[100]) 
{
  char passwd []= "Otptest123";
  //strcpy(passwd,password);
  char cmd[10000];   //to hold the command
  char from[] = "cryptofinal@hotmail.com";    //sender
  char smtpServer[] = "outlook.office365.com:25"; //smtpserver and port
  char username[] = "cryptofinal@hotmail.com";   //username to authenticate with server
  unsigned char seed [128];    // seed
  int body;
  FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate seed 
  fread(seed, sizeof(char)*128,1, urand);
  srand((int)urand);
  body = rand() % 9000 + 1000;     //random 4 digit int
  fclose(urand);

  sprintf(cmd,"sendEmail -f %s -t %s -m %d -s %s -xu %s -xp %s",from,email,body,smtpServer,username, passwd); // prepare command without password 
  system(cmd);
  
  return body;
}


/**************************************************************************
 * SERVER SSL                                                             *
 **************************************************************************/

void server_ssl(SSL *ssl, struct sockaddr_in local, int listen_sd, size_t client_len, struct sockaddr_in sa_cli, unsigned short int port, int sd, int err, char *str, unsigned char Key[16], unsigned char IV[16], X509* server_cert, SSL_CTX* ctx, char buf[4096], FILE *fp, char hash1[32], char hash2[32], unsigned char username[50], unsigned char password[50])
{
SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  
  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    quit(Key, IV, sd, ctx, ssl);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    quit(Key, IV, sd, ctx, ssl);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    quit(Key, IV, sd, ctx, ssl);
    exit(5);
  }


  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset (&local, '\0', sizeof(local));
  local.sin_family      = AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  local.sin_port        = htons (port);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &local,
	     sizeof (local));                   CHK_ERR(err, "here bind");
	     
  /* Receive a TCP connection. */
  printf("...waiting for connection from client\n");
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  printf("Connection from %s\n", inet_ntoa(sa_cli.sin_addr));  
  
  /* ----------------------------------------------- */
 

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);
  err = SSL_accept (ssl);                        CHK_SSL(err);
  
  /* DATA EXCHANGE - Receive message and send reply. */

  err = SSL_read (ssl, buf, 16);                   CHK_SSL(err);
  buf[err] = '\0';

  int i;
  for(i=0;i<16;i++)
      {
	Key[i] = buf[i];
      }
  err = SSL_read (ssl, buf, 16);                   CHK_SSL(err);

  buf[err] = '\0';
  int j;
  for(j=0;j<16;j++)
      {
	IV[j] = buf[j];
      }

  //authentication
   FILE *log;
   log = fopen("log.txt","a");

   while(1){
    int err2;
    err2 = SSL_read (ssl, choice1, 1); 
    if(choice1[0]=='2')
    {
	printf("Quitting");
	quit(Key, IV, sd, ctx, ssl);
    }
    int finalchoice = choice1[0]-'0';
    
    int test=0;
    int err1=0; 
   switch(finalchoice){

   case 1:
    err1 = SSL_read (ssl, username, 32); 
    err= SSL_read (ssl, password, 32);

    Hash("abcdefghijklmhji",password,err,hash2);
    char *hash3;
    hash3=convert_hex(hash2, 32);
    
    if((fp = fopen("Pass.txt","r")) == NULL)
		{
			printf("\nError opening file --- Exiting");
			quit(Key, IV, sd, ctx, ssl);
			exit(1);
		}
    char a[BUFSIZE];
    char b[BUFSIZE];
    a[0]='y';
    b[0]='n';
    while(!feof(fp))
    {
	char abcc[100];
    	 if(fgets(abcc,100, fp)<0);
	
         int flag=0;
	 
	 char test1[err1];
	 while(flag==0)
	 {	
		for(i=0;i<err1;i++)
	 	{
			test1[i]=abcc[i];
	 	}

	 	if(strncmp(username, test1, err1)==0)
	 	{
			 int i;
			 int j=err1+3;
			 for(i=0;i<32;i++)
	 		 {
				hash1[i]=abcc[j];
				j++;
	 		 }
			flag = 1;
	 	}
	 	else
	 	{
		  if(fgets(abcc, 100, fp)<0);
	 	}
         } 
	 char test2[err1];
	 for(i=0;i<err1;i++)
	 	{
			test2[i]=username[i];
	 	}
         test2[err1]='\0';
         if(strncmp(hash3, hash1, 32)==0)
         {
            printf("Correct password ::: %s Authenticated \n", test2);
	    int  z = SSL_write(ssl, a, 8);
            test=1;
         }
         else
         {
            printf("Incorrect password \n");
            int x = SSL_write(ssl, b, 8);
         }
         break;
    }
    fclose(fp);
    if(test == 0)
    {
        printf("User not present-----Exiting");
	quit(Key, IV, sd, ctx, ssl);
        exit(1);
    }

    //OTP
    int OTP;
    int* recvOTP = malloc(4*sizeof(int)); 
    char email[100];
    int oread, pread;
    pread = SSL_read(ssl, email, 50);

    OTP = genOTP(email);

    oread = SSL_read(ssl, recvOTP, sizeof(recvOTP));

    if(OTP==*recvOTP)
    { 
    	int  z = SSL_write(ssl, a, 8);
    	printf("Two Factor Authentication Successful\n");
    }
    else
    {
    	printf("Incorrect OTP\n");
    	int x = SSL_write(ssl, b, 8);
        quit(Key, IV, sd, ctx, ssl);
    	exit(0);
    }
    
   //END OTP
   printf("SERVER READY\n");
   int xxx;
   do{
   
   SSL_read (ssl, choice, 1); 
   int abc = choice[0] - '0';
   xxx=abc;
   FILE *f;
   char abcc[100];
   char c[BUFSIZE];
   char d[BUFSIZE];
   c[0]='y';
   d[0]='n';
   switch(abc){
	case 1: printf("\nFile Access Operations : : :\n");
		SSL_read (ssl, username, 50); 	
		if((f = fopen("FileX.txt","r")) == NULL)
		{
			printf("\nError opening file");
			quit(Key, IV, sd, ctx, ssl);
			exit(1);
		}
		if(fgets(abcc,100, f)<0)
		{
			printf("\nNo contents");
		}
		printf("file contents : %s\n", abcc);
		char *usernametest;
		char test[]="Owner : ";	
		if(!strstr(abcc, username))
		{
			int f1 = SSL_write(ssl, d, 8);
			fprintf(log, "\nFile access check for %s\n", username);
		}	
		else
		{
			int f1 = SSL_write(ssl, c, 8);
			fprintf(log, "\nFile access check for %s\n", username);
		}
		printf("\nWaiting for next input...\n");
		fclose(f);
		break;
	case 2: printf("File Permission Change Operations : : :\n");
		char a[32];
		int k3;
		k3 = SSL_read(ssl, a, 8);
		
		char username1[BUFSIZE]; 
		int k4,k5;
		FILE *f1;
		char abccc[100];
		if((f1 = fopen("FileX.txt","r")) == NULL)
		{
			printf("\nError opening file");
  			quit(Key, IV, sd, ctx, ssl);
			exit(1);
		}
		if(fgets(abccc,100, f1)<0)
		{
			printf("\nNo contents");
		}
		fclose(f1);
		if(a[0]=='1')
		{	printf("abccc %s\n", abccc);
			printf("username is %s\n", username);
			if(!strstr(abccc, username))
				{
				printf("sending no\n");
				int f11 = SSL_write(ssl, d, 8);
				fprintf(log, "\nFile user change decline to %s\n", username);
				}
			else
			{
			printf("sending yes \n");
			int f1 = SSL_write(ssl, c, 8);
			FILE *case2;
			printf("choice 1 \n");
			case2=fopen("FileX.txt","w");
			if(k4 = SSL_read(ssl, username1, 50)<1);
			printf("got Username : %s\n", username1); 
			char c[] = "Owner : ";
			char *final = strcat(c, username1);
			fprintf(case2, "%s", final);
			fclose(case2);
			fprintf(log, "\nFile user change to %s\n", username);
			}
		}
		else if(a[0]=='2')
		{	printf("abccc %s\n", abccc);
			printf("username is %s\n", username);
			if(!strstr(abccc, username))
				{
				printf("sending no\n");
				int f11 = SSL_write(ssl, d, 8);
				fprintf(log, "\nFile user add decline to %s\n", username);
				}	
			else
				{
			printf("sending yes \n");
			int f1 = SSL_write(ssl, c, 8);
			FILE *case2;
			case2 = fopen("FileX.txt","a");
			printf("choice 2 \n");
			if(k5 = SSL_read(ssl, username1, 50)<1);
			printf("got Username : %s\n", username1);
			fprintf(case2, ",%s", username1);
			fclose(case2);
			fprintf(log, "\nFile user added : %s\n", username);
				}
		}
		break;
	case 3: //quit(Key, IV, sd, ctx, ssl);
		break;
	default: 
		printf("");
	}
   }while(xxx!=3);
    		break;
  case 2:	fclose(log);
		quit(Key, IV, sd, ctx, ssl);
		break;
    }

    }


}

/**************************************************************************
 * QUIT AND CLEAN                                                          *
 **************************************************************************/

void quit(unsigned char Key[16],unsigned char IV[16], int sd, SSL_CTX* ctx,
  SSL* ssl)
{
  int i=0;
  for(i=0;i<16;i++)
      {
	Key[i] = 0;
      }

  int j=0;
  for(j=0;j<16;j++)
      {
	Key[j] = 0;
      }
    
  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

  printf("\nKEY and IV cleaned, Socket cleaned\n");
  exit(0);
}

void intHandler(int dummy)
{
quit(Key, IV, sd, ctx, ssl);
exit(0);
}

/**************************************************************************
 * MAIN                                                                   *
 **************************************************************************/

int main(int argc, char *argv[]) {

  signal(SIGINT, intHandler);
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nwrite, plength;
  size_t nread;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];

  // ENCRYPTION VARIABLES

  // HASHING VARIABLES
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len=0;

  //Authentication Variables
   unsigned char username[50];
   unsigned char password[50];
   unsigned char credentials[100];  
   char x[32];
   char *y;
     FILE *fp;
  char hash1[32];
  char hash2[32];

  //PKI

  int err;
  int listen_sd;
  struct sockaddr_in sa;
 struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
   size_t client_len;
  X509*    server_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;

 SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:d")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  if(cliserv==CLIENT){
   
  } 
else {
   server_ssl(ssl, local, listen_sd, client_len, sa_cli, port, sd, err, str, Key, IV, server_cert, ctx, buf, fp, hash1, hash2, username, password);
  }

  return(0);
}
