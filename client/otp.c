int genOTP() {
char passwd []= “PASSWORD";
//strcpy(passwd,password);
        char cmd[10000];   //to hold the command
char from[] = “druva@syr.edu";    //sender
        char to[] = “lodu@syr.edu";   // recepient.
char cc[] = “lodu1@gmail.com";
char smtpServer[] = "smtp-server.syr.edu";//"outlook.office365.com:25";   //smtpserver and port
char username[] = “druva@syr.edu";   //username to authenticate with server
unsigned char seed [128];    // seed
int body;
FILE *urand = fopen("/dev/urandom","r");   //using urandom to generate seed 
fread(seed, sizeof(char)*128,1, urand);
srand((int)urand);
body = rand() % 9000 + 1000;     //random 4 digit int
fclose(urand);


        sprintf(cmd,"sendEmail -f %s -t %s -cc %s -m %d -s %s -xu %s -xp %s",from,to,cc,body,smtpServer,username, passwd); // prepare command without password 
        system(cmd);
//execve(cmd,NULL,NULL);       //execute with execve
        return body;
}





//server OTP process

int OTP; //= malloc(sizeof(int));
int* recvOTP = malloc(4*sizeof(int)); 
int oread;
OTP = genOTP();
//printf("OTP: %d", OTP);
oread = SSL_read(ssl, recvOTP, sizeof(recvOTP));
//printf("recvOTP: %d",*recvOTP);
if(OTP==*recvOTP)
{ 
strcpy(data_buffer,"TT");
SSL_write(ssl,data_buffer, sizeof(data_buffer)); 
printf("Two Factor Authentication Successful\n");
fflush(stdout); 
}
else{
printf("Incorrect OTP\n");
strcpy(data_buffer,"FF");
SSL_write(ssl,data_buffer, sizeof(data_buffer)); //sending 0 size to inform client side that Authentication is not successful
exit(0);
fflush(stdout);
}






//client OTP process

int * sendOTP = malloc(4*sizeof(int));
fflush(stdout);
printf("OTP:\n");
fflush(stdout);
scanf("%d",sendOTP);

SSL_write(ssl, sendOTP, sizeof(sendOTP));

int rcv;
char rcvOTP[8];
rcv = SSL_read(ssl, rcvOTP, 8);
printf("rcv:%s\n",rcvOTP);
fflush(stdout);
        if (rcvOTP[0]=='T' && rcvOTP[1]=='T')
{
fflush(stdout);
printf(" Two factor Authentication Successful\n");
fflush(stdout);
}
else
{
fflush(stdout);
printf("OTP is incorrect, exiting the program\n");
 
close(sd); 
exit(0);
return 0;
}
