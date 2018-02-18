This is the final project for the course Applied Cryptography.
Done By : Dhruv Verma
SUID: 545566937
(C) 2017 gothinski

This project contains two packages : Server and Client

Unzip the client side on your client machine and the server on your server machine. They are two different machines. 

The SSL certificates are self signed created on the server machine. You can create your own cert and use that or use the one which is in the package.

The command to run the client side code is :
Make
./cryptoclient -i eth13 -c www.gothinski.com 

The command to run the server side code is:
Make
./cryptserv -i eth13 -s -d

MAKEFILE for both are included in their zip archives respectively.

Here, you have to make a entry to www.gothinski.com in your /etc/hosts file and map it to the ip address of your server. We use domain name instead of IP to avoid MITM attacks.

eth13 is your interface. Please run ifconfig and change it to your eth card name.

The file access check is being performed on file "FileX.txt" and the password file used in the server is "Pass.txt"

For Client side local server authentication use the password Infi2012!
The two included users are :
user 1: 
uname: dhruv
password: verma

User 2:
uname: ashu
password: rana

please install gcc and "sendemail" using apt-get install sendemail for the OTP service to work.

OTP username password has been setup already.
