/**************************************************************************
 * Crypto_Project.c                                                       *
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

#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 77777

#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

unsigned char Key[16],IV[16];
  int sd;
  SSL_CTX* ctx;
  SSL*     ssl;

int choice;

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

/***************************************************************************
 * KEY GEN and IV GEN                                                     *
 **************************************************************************/

void gen_key(unsigned char *key)
{
  int i;
  unsigned char seed [128];    // seed
  int body;
  FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate seed 
  fread(seed, sizeof(char)*128,1, urand);
  srand((int)urand);
  for(i=0;i<16;i++)
    key[i]=65+(rand()%26);
}

void gen_iv(unsigned char *iv)
{
  int i;
  unsigned char seed [128];    // seed
  int body;
  FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate seed 
  fread(seed, sizeof(char)*128,1, urand);
  srand((int)urand);
  srand(time(NULL));
  for(i=0;i<16;i++)
    iv[i]=48+(rand()%10);
}

/**************************************************************************
 * Hostname to ip resolve                                                  *
 **************************************************************************/

void hostnametoip(char *hostname,char *remote_ip)
{
   struct hostent *serverhost;
  struct in_addr **addr_list;
  int i=0;
  serverhost = gethostbyname(hostname);
  if(serverhost == NULL)
    printf("Hostname Failed\n");
  else
  {
    addr_list = (struct in_addr **)serverhost->h_addr_list;
    for(i=0;addr_list[i]!=NULL;i++)
    {
      strcpy(remote_ip,inet_ntoa(*addr_list[i]));
    }
  }
}

/**************************************************************************
 * HASH AND CHECKHASH                                                     *
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
 * Client SSL                                                             *
 **************************************************************************/

void client_ssl(SSL *ssl, struct sockaddr_in remote, char remote_ip[16], int sd, unsigned short int port, int err, char *str, char *hostname[17], unsigned char Key[16], unsigned char IV[16], X509* server_cert, SSL_CTX* ctx, char *y, char x[32], unsigned char credentials[100], char password[50], unsigned char username[50], char buf [4096])
{
//SSL

  
  char username1[50];
     SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);


 /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
  
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
  memset (&remote, '\0', sizeof(remote));
  remote.sin_family      = AF_INET;
  remote.sin_addr.s_addr = inet_addr(remote_ip);   
  remote.sin_port        = htons(port);        

  err = connect(sd, (struct sockaddr*) &remote,
		sizeof(remote));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
    
  
  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  SSL_set_fd (ssl, sd);
  err = SSL_connect (ssl);                     CHK_SSL(err);
  
  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);

  X509_NAME *subject =X509_get_subject_name(server_cert);
  CHK_NULL(subject);
  int nid_cn = OBJ_txt2nid("CN");
  char common_name[256];
  X509_NAME_get_text_by_NID(subject,nid_cn,common_name,256);
  //Common Name Check
  if(strcmp(common_name, hostname)==0)
	{
		printf ("MATCHED SERVER CERTIFICATE\n");
	}
  else
	{
		printf("MISMATCH SERVER CERTIFICATE\n");
 		quit(Key, IV, sd, ctx, ssl);
		exit(1);
	}
  

  OPENSSL_free (str);
  X509_free (server_cert);

  //KEY and IV Generation
  
  gen_key(Key);
  gen_iv(IV);
  
  //sending key
  int i;
  char temp[BUFSIZE];
  for(i=0;i<16;i++)
      {
	temp[i] = Key[i];
      }
  i = SSL_write(ssl, temp, 16);
  CHK_SSL(i);
  //sending iv
   
  char temp1[BUFSIZE];
  for(i=0;i<16;i++)
      {
	temp1[i] = IV[i];
      }
  i = SSL_write(ssl, temp1, 16);
  CHK_SSL(i);


  //authentication


   while(1){
  printf("Welcome to the Secure Distributed File System written by Dhruv Verma\n");
  printf("Please choose a option : \n");
  printf("1: Authenticate user and run code \n");
  printf("2: Quit program\n");
  char mainchoice[32];
  scanf("%s", mainchoice);

  SSL_write(ssl, mainchoice, 1);

  int finalchoice;
  finalchoice = mainchoice[0] - '0';
  switch(finalchoice)
  {
  case 1:
    printf("Enter Username : ");
    scanf("%s", username);
    username[strlen(username)]='\0';

    password= getpass("Enter Password : ");
    password[strlen(password)]='\0';
   
    int k=0;
    k=SSL_write(ssl, username, strlen(username));
    
    int l1=0;
    l1=SSL_write(ssl, password, strlen(password));
   char recieve[32];
   int k1;
   k1=SSL_read(ssl, recieve, 8);
   if(recieve[0]=='y')
	{
		printf("Correct username and password\n");
	}
   else
	{
		printf("Incorrect credentials----Quitting\n");
		quit(Key, IV, sd, ctx, ssl);
		exit(0);
	}

    //OTP
    int * sendOTP = malloc(4*sizeof(int));
    printf("Enter Email ID to send the code :\n");
    char email[50];
    scanf("%s",email);
    
    int z = SSL_write(ssl, email, 50);

    printf("OTP:\n");
    scanf("%d",sendOTP);
    SSL_write(ssl, sendOTP, sizeof(sendOTP));

    int rcv;
    char rcvOTP[8];
    rcv = SSL_read(ssl, rcvOTP, 8);
    if (rcvOTP[0]=='y')
    {
    	printf(" Two factor Authentication Successful\n");
    }
    else	
    {
    printf("OTP is incorrect, exiting the program\n");
    quit(Key, IV, sd, ctx, ssl);
    exit(0);
    return 0;
    }

   //END OTP

   printf("CLIENT READY\n");
   int xxx;
   do{
   printf("\nEnter your choice :\n");
   printf("1: Access File\n");
   printf("2: Modify Permissions of a file\n");
   printf("3: Logout \n");
   char tempchoice[32];
   printf("Enter here : ");
   scanf("%s", tempchoice);
   SSL_write(ssl, tempchoice, 1);
   choice = tempchoice[0] - '0';
   xxx=choice;
   char answer[32];
   int k2;
   switch(choice){
        case 1: printf("\nFile Access Operations : : :\n");
		SSL_write(ssl, username, 50);
		k2 = SSL_read(ssl, answer, 8);
		printf("the answer is : %s\n", answer);
		
		if(answer[0]=='y')	
		{
			printf("Acess Granted to user : %s\n", username);
		}
		else
		{
			printf("Access Denied to user : %s\n", username);
		}
		break;
	case 2: printf("\nFile Permission Change Operations : : :\n");
		printf("Enter your choice : \n");
		printf("1 : Change owner of your file \n");
		printf("2 : Add a user to your file \n");
		printf("3 : return \n");
		char m[32];
		printf("Enter here : ");
		scanf("%s", m);
		printf("send %s\n",m);
		SSL_write(ssl, m, 1);
		int choice1 =m[0] - '0';
		//declarations
		char c[100];
  		char d[100];
		int k3,k4;
		int x1;
		//end declarations
		switch(choice1)
		{
			case 1:	//change ownership
				printf("\nChanging Ownership : : :\n");
				k2 = SSL_read(ssl, answer, 8);
				if(answer[0]=='n')
				{
					printf("\nUser doesnt have rights\n");
				}
				else
				{
				printf("Enter the name of the user : ");
				scanf("%s", username1);
   				username1[strlen(username1)]='\0';
				x1= sizeof(username1);
				k3= SSL_write(ssl, username1, x1);
				printf("Username sent : %s\n", username1);
				printf("\n Ownership Changed \n");
				}
				break;
			case 2: //add owner
				printf("\nAdding Permissions : : :\n");
				k2 = SSL_read(ssl, answer, 8);
				if(answer[0]=='n')
				{
					printf("User doesnt have rights\n");
				}
				else
				{
				printf("Enter the name of the user : ");
				scanf("%s", username1);
   				username1[strlen(username1)]='\0';
				x1= sizeof(username1);
				k3= SSL_write(ssl, username1, x1);
				printf("Username sent :l %s\n", username1);	
				}		
				break;
			case 3: break;
			default:printf("Incorrect Input. Exiting. \n");
				break;	
		}
		break;
	case 3: printf("\n Logging Out \n");
		//quit(Key, IV, sd, ctx, ssl);
		break;
	default: 
		printf("Incorrect Input. Exiting. \n");

	}
	
   }while(xxx!=3);
	  break;
  case 2: printf("Quitting \n");
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
  printf("\nKEY and IV cleaned, Sockets cleaned\n");
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


  // HASHING VARIABLES
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len=0;

  //Authentication Variables
   unsigned char username[50];
   char password[50];
   unsigned char credentials[100];  
   char x[32];
   char *y;
     FILE *fp;
  char hash1[32];
  char hash2[32];
  
    int fd[2];

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
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);                        
  CHK_NULL(ctx);
  CHK_SSL(err);
  char *hostname[17];


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
        strncpy(hostname,optarg, 17);
        hostnametoip(hostname, remote_ip);
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
    /* Client, try to connect to server */
  client_ssl(ssl, remote, remote_ip, sd, port, err, str, hostname, Key, IV, server_cert, ctx, y, x, credentials, password, username, buf);				    

  } 
else {

  }
  return(0);
}
