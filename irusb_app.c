
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <sys/fcntl.h>
#include <syslog.h>
#include <poll.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "globals.h"
#include "process_uartstr.h"

#define SSDP_TTL                32 
#define SSDP_MULTI_ADDR         "239.255.255.250"
#define SSDP_PORT               1904

#define GC_TTL                32 
#define GC_MULTI_ADDR         "239.255.250.250"
#define GC_PORT               9131



// globals local to this file

int serial_sock[MAX_SINK];  // connected socket
int serial_rxcnt[MAX_SINK];  // connected socket
int connect_sock[48];  // connected socket
int gcconnect_sock[48];  // connected socket
int client_sockfd;
int restart_app;
int ssdp_ssocket;
int gc_ssocket;
char muuid[128];
char gcuuid[128];

int webcapture;
// firebase
FILE* fds_fb_stream;
FILE* fdr_fb_stream;
char fb_buf[1300];
int fb_len, fb_rp, fb_wp;
pid_t fb_pid;
int fdr_fb[2];
int fds_fb[2];
int start_fb_timer;

char infname[32];

// =================================================================================================
// IRUSB Linux app, copyright 2017 Video Storm LLC
//   Closed source, all rights reserved

//  web/linux socket for device communication
//  ethernet socket 9093 for local network comm
//    will add cloud com later

//  support for firmware update
//  support for multiple device control

void start_firebase(){
        fdr_fb[0]=0;
        fdr_fb[1]=0;
        fds_fb[0]=0;
        fds_fb[1]=0;
        fb_rp = 0;
        fb_wp = 0;
        fb_buf[0]=13;
	start_fb_timer=-1;
        // if firebase installed, enabled, and email/password set then run
        int fben=0;
        char fbun[256];
        char fbpw[256];
        fben =  read_fbcreds(fbun, fbpw);
	fb_pid=0;

        if ((fben>0)&&(strlen(fbun)>3)&&(strlen(fbpw)>3)){

                syslog(LOG_INFO,"Starting NetPlay Cloud");
                // now run firebase
                pipe(fds_fb);
                pipe(fdr_fb);
                fb_pid = fork();
                if (fb_pid==0){
                        //child
                        close(fdr_fb[0]);
                        close(fds_fb[1]);
                        // we will use STDIN/STDOUT
                        dup2(fds_fb[0],0);    //STDIN
                        dup2(fdr_fb[1],1);    //STDOUT
                        if (execl("../../python/runNetPlayIrUSB.py", "../../python/runNetPlayIrUSB.py",  fbun, fbpw, muuid, NULL)){exit(1);}
                        exit(0);
                }
                // parent continues
                close(fds_fb[0]);
                close(fdr_fb[1]);
                fds_fb_stream = fdopen(fds_fb[1],"w");
                fdr_fb_stream = fdopen(fdr_fb[0],"r");
        }
}


static void SignalHandler(int iSignal)
{
        if (iSignal == SIGPIPE)
        {
                syslog(LOG_INFO, "SIGPIPE error!!\n");

        }
        else if (iSignal == SIGTERM || iSignal == SIGINT)
        {
                syslog(LOG_INFO, "Terminating...\n");
		// should I kill children here???
		// need to explicitely close serial ports
		int i;
		for(i=0;i<MAX_SINK;i++){
		if(serial_sock[i]>0){
			set_defaultmode(serial_sock[i]);
			close(serial_sock[i]);
		}
		}
		exit(0);
        }
        else if (iSignal == SIGSEGV || iSignal == SIGBUS || iSignal == SIGABRT || iSignal == SIGILL || iSignal == SIGFPE)
        {
                syslog(LOG_ERR, "ERROR, signal is %d\n",iSignal);
		// should I kill children here???
		exit(0);
        }
        else if (iSignal == SIGCHLD)
	{
		// child terminated
		pid_t deadkid;
		deadkid = waitpid(-1, NULL, WNOHANG);

		// see what child it is
		//if ((sddp_pid)&&(deadkid==sddp_pid)){
                //	syslog(LOG_INFO, "Received SIGCHLD from sddpd\n");
		//}
		// firebase child do nothing
                if ((fb_pid)&&(deadkid==fb_pid)){
                        syslog(LOG_INFO, "Received SIGCHLD from firebase\n");
                        fb_pid=0;
                        if (fdr_fb[0]>0){close(fdr_fb[0]);}
                        fdr_fb[0]=0;
			if (restart_app==0){
				start_fb_timer=300;
			}
                }


	}
}



int CheckLink(char *ifname) {
    //int state = -1;
    int socId = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (socId < 0){
	syslog(LOG_INFO,"Could not create sock for %s",ifname);
	return -1;
    }

    struct ifreq if_req;
    (void) strncpy(if_req.ifr_name, ifname, sizeof(if_req.ifr_name));
    int rv = ioctl(socId, SIOCGIFFLAGS, &if_req);
    close(socId);

    if ( rv == -1) {
	syslog(LOG_INFO,"IOCTL failed for %s",ifname);
	return -1;
    }

    return (if_req.ifr_flags & IFF_UP) && (if_req.ifr_flags & IFF_RUNNING);
}

int openGCSendSocket(){
    // Setup generic send socket used for unicast and multicast notify messages
        int socket_opt;
    gc_ssocket = socket(AF_INET, SOCK_DGRAM,  0); // IPPROTO_UDP implicit from SOCK_DGRAM
    if (ssdp_ssocket < 0)
    {
        printf("Failed to create GC send socket %d", gc_ssocket);
        return -1;
    }

    // Setup TTL (time to live)
    socket_opt = GC_TTL;
    if (setsockopt(gc_ssocket, IPPROTO_IP, IP_MULTICAST_TTL, &socket_opt, sizeof(int)))
    {
        printf("Can't set IP_MULTICAST_TTL on send socket");
        return -1;
    }else{
        return 0;
    }
}

int writeGCSocket(char *msg, int len, struct sockaddr_in *sa){
// UDP multicast is connectionless, so we use the sendto funtion instead of connecting
//============================================================================================

    struct sockaddr_in send_to;
    struct in_addr iface_addr; 
        
    iface_addr = sa->sin_addr;
    //iface_addr.s_addr = inet_addr(((irusbsink *)m_global)->Get_ip());
    if (setsockopt(gc_ssocket, IPPROTO_IP, IP_MULTICAST_IF, &iface_addr, sizeof(iface_addr)) < 0)
    {
        printf("Multicast setting interface %s failed", inet_ntoa(iface_addr));
        return -1;
    }
    
    send_to.sin_family = AF_INET;
    send_to.sin_port = htons(GC_PORT);
    send_to.sin_addr.s_addr = inet_addr(GC_MULTI_ADDR);
    //syslog(LOG_INFO,"Sending ssdp packet: %s",msg);
    if (sendto(gc_ssocket, msg, len, 0, (struct sockaddr *)&send_to, sizeof (struct sockaddr_in)) > 0)
    {
        return 1;
    }
    else
    {
        printf("Multicast send failed %s", strerror(errno));
        return -1;
    }
}


int sendGCPacket(char * uuid, char const * inf){
   char buf[1024];
   char *ipaddr;
   int r;

   // get IPADDR of interface inf
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
          if (strncmp(ifa->ifa_name,inf,strlen(inf))==0){
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            ipaddr = inet_ntoa(sa->sin_addr);
            //printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
          }
        }
    }

    freeifaddrs(ifap);

   // no CRC for now, rely on UDP crc
   //sprintf(buf,"%s \n%s \n\%s \n%d \n%d \n0 \n\r",not_iden,uuid,ipaddr,port,type);
   sprintf(buf,"AMXB<-UUID=%s><-SDKClass=Utility><-Make=GlobalCache><-Model=iTachWF2IR><-Revision=710-1001-05><-Pkg_Level=GCPK001><-Config-URL=http://%s><-PCB_PN=025-0026-06><-Status=Ready>",uuid,ipaddr);
   r = writeGCSocket(buf,strlen(buf),sa);
   return r;
}

void closeGCSendSocket(){
        if (gc_ssocket>0){
                close(gc_ssocket);
		gc_ssocket=0;
        }
}

int openSsdpSendSocket(){
    // Setup generic send socket used for unicast and multicast notify messages
        int socket_opt;
    ssdp_ssocket = socket(AF_INET, SOCK_DGRAM,  0); // IPPROTO_UDP implicit from SOCK_DGRAM
    if (ssdp_ssocket < 0)
    {
        printf("Failed to create VS send socket %d", ssdp_ssocket);
        return -1;
    }

    // Setup TTL (time to live)
    socket_opt = SSDP_TTL;
    if (setsockopt(ssdp_ssocket, IPPROTO_IP, IP_MULTICAST_TTL, &socket_opt, sizeof(int)))
    {
        printf("Can't set IP_MULTICAST_TTL on send socket");
        return -1;
    }else{
        return 0;
    }
}

int writeSsdpSocket(char *msg, int len, struct sockaddr_in *sa){
// UDP multicast is connectionless, so we use the sendto funtion instead of connecting
//============================================================================================

    struct sockaddr_in send_to;
    struct in_addr iface_addr; 
        
    iface_addr = sa->sin_addr;
    //iface_addr.s_addr = inet_addr(((irusbsink *)m_global)->Get_ip());
    if (setsockopt(ssdp_ssocket, IPPROTO_IP, IP_MULTICAST_IF, &iface_addr, sizeof(iface_addr)) < 0)
    {
        printf("Multicast setting interface %s failed", inet_ntoa(iface_addr));
        return -1;
    }
    
    send_to.sin_family = AF_INET;
    send_to.sin_port = htons(SSDP_PORT);
    send_to.sin_addr.s_addr = inet_addr(SSDP_MULTI_ADDR);
    //syslog(LOG_INFO,"Sending ssdp packet: %s",msg);
    if (sendto(ssdp_ssocket, msg, len, 0, (struct sockaddr *)&send_to, sizeof (struct sockaddr_in)) > 0)
    {
        return 1;
    }
    else
    {
        printf("Multicast send failed %s", strerror(errno));
        return -1;
    }
}


int sendPacket(char const * not_iden, char * uuid, char const * inf, int port, int type){
   char buf[1024];
   char *ipaddr;
   int r;

   // get IPADDR of interface inf
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
          if (strncmp(ifa->ifa_name,inf,strlen(inf))==0){
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            ipaddr = inet_ntoa(sa->sin_addr);
            //printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
          }
        }
    }

    freeifaddrs(ifap);

   // no CRC for now, rely on UDP crc
   sprintf(buf,"%s \n%s \n\%s \n%d \n%d \n0 \n\r",not_iden,uuid,ipaddr,port,type);
   r = writeSsdpSocket(buf,strlen(buf),sa);
   return r;
}

void closeSsdpSendSocket(){
        if (ssdp_ssocket>0){
                close(ssdp_ssocket);
		ssdp_ssocket=0;
        }
}

void SendID(){
        printf("Sending identify\n");

        openSsdpSendSocket();
        sendPacket("IDENTIFY",muuid,infname,9091,0);
        closeSsdpSendSocket();
}


void process_rxcode(char *buf, int buf_len, char *devid, int rptcd){
	// receive RX and send to all connect_sock[48]
	//  convert to hex code, then send as QSIRPULSE000 thecode\cr
	char cmd[8196];
	char pulse[16];
	//char ccmd[256];
	int i;
	unsigned int hi,lo;

	cmd[0]=0;

	if ((buf[0]=='O') && (buf[1]=='N')){
		sprintf(cmd,"QMOTIONON %s\r",devid);
	}else if ((buf[0]=='O') && (buf[1]=='F') && (buf[2]=='F')){
		sprintf(cmd,"QMOTIONOFF %s\r",devid);
	}else{
	if (rptcd>30){
		sprintf(cmd,"QSIRPULSE000 0000 %04x 0000 %04x ",109,buf_len/4);
	}else{
		sprintf(cmd,"QSIRPULSE000 0000 %04x %04x 0000 ",109,buf_len/4);
	}

	for (i=0;i<(buf_len/4);i++){
		hi = ((buf[i*4])<<8) + buf[i*4+1];
		lo = ((buf[i*4+2])<<8) + buf[i*4+3];
		// convert from 23.   us   to 26.3158 us
		hi = (hi*21333)/26315;
		lo = (lo*21333)/26315;

		// error check
		if (hi<4){hi=4;}
		if (hi>0x8000){hi=0x8000;}
		if (lo<4){hi=4;}
		if (lo>0x8000){lo=0x8000;}

		sprintf(pulse,"%04x %04x ",hi,lo);
		strcat(cmd,pulse);
	}
	strcat(cmd,"\r");
	}

	if (strlen(cmd)>2){
	#ifdef INC_FB
	if (fds_fb[1]>0){
		// if cloud connected, look for RX code match
		i = find_rxcode(devid, cmd, ccmd);
		if (i>0){
			write(fds_fb[1],ccmd,strlen(ccmd));
		}
	}
	#endif

	// now send
	for (i=0;i<48;i++){
		if (connect_sock[i]>0){
			write(connect_sock[i],cmd,strlen(cmd));
		}
	}
	if (webcapture>0){
		if ((webcapture==1)&&(client_sockfd>0)){
			syslog(LOG_INFO,"Wrote webcap data");
			write(client_sockfd,cmd,strlen(cmd));
			webcapture--;
		}
		if (webcapture>1){webcapture--;}
	}
	}
}


int poll_ret(int fds, int max_set, struct pollfd *polll){
	int i;
	for(i=0;i<max_set;i++){
		if (polll[i].fd == fds){
			return polll[i].revents;
		}
	}
	return 0;
}

int poll_checkdup(int max_set, struct pollfd *polll){
	int i,j;
	for(i=0;i<max_set;i++){
	for(j=0;j<max_set;j++){
		if ((i!=j)&&(polll[i].fd == polll[j].fd)){
			syslog(LOG_ERR,"Duplicate FD %d and %d, fd %d",i,j,polll[i].fd);
			return 1;
		}
	}
	}
	return 0;
}


void poll_clear(int max_set, struct pollfd *polll){
        int i;
        for(i=0;i<max_set;i++){
                polll[i].revents=0;
        }
}



int mainloop(int verb)
{
	int i,j,y;
	char  sbuffer[2048];

	//fd_set set,master_set;
	int max_master, max_set;
	struct pollfd poll_list[MAX_SINK+114];


	struct timeval spec;
	long int last_sec, delta_sec;

	int powerup_init;

	

	// ethernet socket
	int sock;         // listening socket
	struct sockaddr_in serv_name;
	//size_t len;
	socklen_t len;
	char eth_buf[48][1300];
	int eth_len[48], eth_rp[48], eth_wp[48], eth_q[48];

	// gc socket
        int gcsock;         // listening socket
        struct sockaddr_in gcserv_name;
        //size_t gclen;
        socklen_t gclen;
        char gc_buf[48][1300];
        int gc_len[48], gc_rp[48], gc_wp[48], gc_q[48];


	// web socket
	int server_sockfd;
	struct sockaddr_un server_address;
	struct sockaddr_un client_address;
	//size_t server_len;
	//size_t client_len;
	socklen_t server_len;
	socklen_t client_len;
	char web_buf[1300];
	int web_len,web_rp, web_wp;


	// serial socket
	
	char serial_buf[MAX_SINK][1300];
	int serial_len[MAX_SINK], serial_rp[MAX_SINK], serial_wp[MAX_SINK];


	char process_buf[1300];
	char *cmd_buf;
	int process_len;
	int cmd_len;
	int processed, last_processed;
	int vssd_timer;
	int gc_timer;
	int poll_timer;

	openlog("IRUSB", LOG_CONS | LOG_PID, LOG_LOCAL0);
	

	// signal handling
	signal(SIGTERM, SignalHandler);    // terminiation
	signal(SIGPIPE, SignalHandler);    // PIPE io error
	signal(SIGCHLD, SignalHandler);    // child terminated
	signal(SIGINT, SignalHandler);	   // interrupt, like cntr-c 
	signal(SIGBUS, SignalHandler);	    
	signal(SIGABRT, SignalHandler);	    
	signal(SIGSEGV, SignalHandler);	    
	signal(SIGFPE, SignalHandler);	    
	signal(SIGILL, SignalHandler);	    
	


	//======================  init  ===============================================

	for (i=0;i<(MAX_SINK);i++){
		//sink_stat[i].no_lic=0;
		serial_sock[i]=0;
		serial_rxcnt[i]=0;
	}

	restart_app = 0;
	powerup_init = 1;
	ssdp_ssocket=0;
	vssd_timer=120;
	gc_timer=600;
	poll_timer=240;
	webcapture=0;

	fdr_fb[0]=-1;
	fdr_fb[1]=-1;
	fds_fb[0]=-1;
	fds_fb[1]=-1;


      //=======================    READ config    ===============================================

	//vm_read_channel_st();

        //======================  daemonize to disconnect from terminal  ====================================

	if (verb<1){
        umask(0);
        setsid();
	//  need to run from bin directory
        //chdir("/root/vrx/bin");
	// we will use dup2 to close all the STD files and then reopen them to NULL
        //  this will prevent reuse of FD 0,1,2
        //    FD = 0 causes bugs in our code.  The others prevent accidental writes given STDOUT/STDERR constants..

        //close(STDIN_FILENO);
        //close(STDOUT_FILENO);
        //close(STDERR_FILENO);

	dup2(open("/dev/null", O_RDONLY), 0);
        dup2(open("/dev/null", O_WRONLY), 1);
        dup2(open("/dev/null", O_WRONLY), 2);
	}
     
      //=======================    READ MAC       ===============================================
unsigned int macint[6];
FILE  *MemFP;
char cmdlin[512];
char *news;


MemFP = fopen("/proc/cmdline","r");
if (!MemFP){
        printf("Cannot access memory\n");
        return 0;
}
	fgets(cmdlin,500,MemFP);
	news = strstr(cmdlin,"macaddr=");

	if (news){sscanf((char*)(news+8), "%x:%x:%x:%x:%x:%x ",&macint[0],&macint[1],&macint[2],&macint[3],&macint[4],&macint[5]);}

sprintf(sbuffer,"%02x%02x%02x%02x%02x%02x",macint[0],macint[1],macint[2],macint[3],macint[4],macint[5]);

	sprintf(muuid,"VideoStorm-%s-%s","IrUSB",sbuffer);
	sprintf(gcuuid,"GlobalCache_%s",sbuffer);


//=========================================================================================================
//   find interface used
	sprintf(infname,"eth0");

	if (CheckLink("eth0")>0){
		sprintf(infname,"eth0");
		syslog(LOG_INFO,"Selected eth0 as IP interface");
	}else if (CheckLink("wlan0")>0){
		sprintf(infname,"wlan0");
		syslog(LOG_INFO,"Selected wlan0 as IP interface");
	}else if (CheckLink("wlp2s0")>0){
		sprintf(infname,"wlp2s0");
		syslog(LOG_INFO,"Selected wlp2s0 as IP interface");
	}


//========== Firebase implementation ==========================================================================

#ifdef INC_FB
	start_firebase();
#endif


//=========================================================================================================


        // INIT WEB SERVER socket
	web_wp=0;
	web_rp=0;
	web_buf[0]=13;
	client_sockfd = 0;
	server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);       // open unix socket
	if (server_sockfd <0){
		fprintf(stderr,"Can not open web socket!/n");
		syslog(LOG_ERR,"Can not open web socket!/n");
                close(server_sockfd);
        }

	bzero(&server_address, sizeof(server_address));
	bzero(&client_address, sizeof(client_address));
	server_address.sun_family = AF_UNIX;
#ifdef INC_FB
	strcpy(server_address.sun_path, "../../data/irweb_socket");   // setup path to file for socket
	unlink("../../data/irweb_socket");
#else
	strcpy(server_address.sun_path, "../data/irusb_socket");   // setup path to file for socket
	unlink("../data/irusb_socket");
#endif
	server_len = sizeof(server_address);
	if (bind(server_sockfd, (struct sockaddr *)&server_address, server_len)<0){   // bind to file
		fprintf(stderr, "Error binding web socket! Errnum %d\n",errno);
		syslog(LOG_ERR, "Error binding web socket! Errnum %d\n",errno);
                close(server_sockfd);
		server_sockfd=-1;
	}

	if (server_sockfd >0){
	listen(server_sockfd,1);  // listen for 1 connection
	printf("Web socket started\n");
	}

#ifdef INC_FB
	system("chmod a+w ../../data/irweb_socket\n");
#else
	system("chmod a+w ../irusb_socket\n");
#endif

//=========================================================================================================
	// ethernet socket

	for (i=0;i<48;i++){
	eth_wp[i] = 0;
	eth_rp[i] = 0;
	eth_q[i] = 0;
	eth_buf[i][0]=13;
	connect_sock[i] = 0;
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);    //open tcp socket
	if (sock <0){
		fprintf(stderr,"Can not open TCP socket!/n");
		syslog(LOG_ERR,"Can not open TCP socket!/n");
		close(sock);
	}
	// set socket options
	y =1;
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&y, sizeof(y));   // keepalive on
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&y, sizeof(y));  // allows faster reconnect to socket
	
	// set name as the physical address of the socket descriptor (sock)
	bzero(&serv_name, sizeof(serv_name));  // init address struct
	serv_name.sin_family = AF_INET;
	serv_name.sin_port = htons(9093);		
	
	// bind the socket address to the socket descriptor
	if (bind(sock, (struct sockaddr *)&serv_name, sizeof(serv_name))<0){
		fprintf(stderr, "Error naming ethernet channel! Errnum %d\n",errno);
		syslog(LOG_ERR, "Error naming ethernet channel! Errnum %d\n",errno);
		close(sock);
	}

	// THIS will fail if mdns_service is currently running....  WHY????
	if (sock>0){
	listen(sock,1);  // listen for 1 connection on the socket  (queue is 1)  non-blocking
	printf("TCP control port started\n");
	}	

//=========================================================================================================
	// gc socket

	for (i=0;i<48;i++){
	gc_wp[i] = 0;
	gc_rp[i] = 0;
	gc_q[i] = 0;
	gc_buf[i][0]=13;
	gcconnect_sock[i] = 0;
	}
	gcsock = socket(AF_INET, SOCK_STREAM, 0);    //open tcp socket
	if (gcsock <0){
		fprintf(stderr,"Can not open GC socket!/n");
		syslog(LOG_ERR,"Can not open GC socket!/n");
		close(gcsock);
	}
	// set socket options
	y =1;
	setsockopt(gcsock, SOL_SOCKET, SO_KEEPALIVE, (char *)&y, sizeof(y));   // keepalive on
        setsockopt(gcsock, SOL_SOCKET, SO_REUSEADDR, (char *)&y, sizeof(y));  // allows faster reconnect to socket
	
	// set name as the physical address of the socket descriptor (sock)
	bzero(&gcserv_name, sizeof(gcserv_name));  // init address struct
	gcserv_name.sin_family = AF_INET;
	gcserv_name.sin_port = htons(4998);		
	
	// bind the socket address to the socket descriptor
	if (bind(gcsock, (struct sockaddr *)&gcserv_name, sizeof(gcserv_name))<0){
		fprintf(stderr, "Error naming gc ethernet channel! Errnum %d\n",errno);
		syslog(LOG_ERR, "Error naming gc ethernet channel! Errnum %d\n",errno);
		close(gcsock);
	}

	// THIS will fail if mdns_service is currently running....  WHY????

	if (gcsock>0){
	listen(gcsock,1);  // listen for 1 connection on the socket  (queue is 1)  non-blocking
	printf("GC control port started\n");
	}	


//=========================================================================================================
	// serial sockets
	sleep(60);  // wait 1 minutes for boot to finish before init

	char tmpn[128];
	struct termios uart1opt;

	for (i=0;i<MAX_SINK;i++){

 	serial_wp[i]=0;
        serial_rp[i]=0;
        serial_buf[i][0]=13;
	sprintf(tmpn,"/dev/ttyACM%d",i);
        serial_sock[i] = open(tmpn,O_RDWR | O_NOCTTY | O_SYNC | O_NDELAY);
        //serial_sock[i] = open(tmpn,O_RDWR | O_NOCTTY | O_SYNC);
        if (serial_sock[i] > 0) {
                printf("Found USB %d\n",i);
                syslog(LOG_ERR,"Found USB %d",i);
        
        	tcgetattr(serial_sock[i], &uart1opt);
        	cfsetispeed(&uart1opt, B115200);
        	cfsetospeed(&uart1opt, B115200);
        	uart1opt.c_cflag = B115200 | CS8 | CREAD | CLOCAL;
        	uart1opt.c_iflag = IGNPAR;              // dont want ICRNL (map cr=>nl)
        	uart1opt.c_lflag = 0;                           // set auto echo  NOT
        	uart1opt.c_oflag = 0;
		tcflush(serial_sock[i], TCIFLUSH);
        	tcsetattr(serial_sock[i], TCSANOW, (struct termios *) &uart1opt);
		usleep(1000);
		set_samplemode(serial_sock[i]);
	}
	}

//=========================================================================================================

        // continuous monitoring loop
	printf("Starting monitoring loop\n");
	syslog(LOG_INFO,"Starting monitoring loop\n");

	// out loop using select() to efficiently monitor the IO
	//  select is a BLOCKING call to monitor all the pipes attached to it
	//   it will SLEEP this process until something happens on a pipe
	//   the timeout is for the occasional LED update or such

	
	max_master=0;
	max_set=0;
	for (i=0;i<(MAX_SINK+114);i++){
		poll_list[i].fd = 0;
		//poll_list[i].events = POLLIN | POLLPRI | POLLERR | POLLHUP;
		poll_list[i].events = POLLIN | POLLERR | POLLHUP;
	}


	
	// ethernet listen socket
	if(sock>0){
		poll_list[max_master].fd=sock;
		max_master++;
	}
	
	// gc listen socket
	if(gcsock>0){
		poll_list[max_master].fd=gcsock;
		max_master++;
	}
	

	// web listen socket
	if(server_sockfd>0){
		poll_list[max_master].fd=server_sockfd;
		max_master++;
	}


	while (restart_app==0){

		//printf("Loop beep\n");

		// check all pipes
		//  int select(int nfds, fd_set *read_fds, fd_set *write_fds, fs_set *except-fds, struct timeval *timeout)
		//             read_fds is set to read, write_fds is set to write, except-fds is checked for errors?
		//             each set will be overwritten by the set that has data ready
		//     return -1 on error, 0 on timeout, else # of ready fds in the set
		max_set = max_master;
		for(i=0;i<48;i++){
		if (connect_sock[i]>0){
			// add connected ethernet socket
			poll_list[max_set].fd=connect_sock[i];
			max_set++;
		}
		}
		for(i=0;i<48;i++){
		if (gcconnect_sock[i]>0){
			// add connected ethernet socket
			poll_list[max_set].fd=gcconnect_sock[i];
			max_set++;
		}
		}
		if (client_sockfd>0){
			// add connected web socket
			poll_list[max_set].fd=client_sockfd;
			max_set++;
                }
		if (fdr_fb[0]>0){
                	poll_list[max_set].fd=fdr_fb[0];
                	max_set++;
        	}

		// serial sockets
		for (i=0;i<(MAX_SINK);i++){
			if (serial_sock[i]>0){
				poll_list[max_set].fd=serial_sock[i];
				max_set++;
			}
		}
		
		if (max_set > (MAX_SINK+114)){syslog(LOG_ERR,"Max set too high %d",max_set);}
		poll_clear(max_set, poll_list);

		// make sure no duplicate FDs, could cause hang!!
		poll_checkdup(max_set, poll_list);

		y = poll(poll_list,max_set,2000);
		//printf("Select with %d returned: %d\n",max_fid, y);
		// grab time elapsed since last call
		gettimeofday(&spec, NULL);
		delta_sec = spec.tv_sec - last_sec;
		if (delta_sec > 4){delta_sec=4;}
		if (delta_sec < 0){delta_sec=0;}
		last_sec = spec.tv_sec;

		if (y < 0){
			// error
			fprintf(stderr,"Error while waiting for pipe data!  Errno:%d\n",errno);
			syslog(LOG_ERR,"Error while waiting for pipe data!  Errno:%d\n",errno);
			sleep(4);
		}else if (y >0){
			printf("Poll with %d returned: %d\n",max_set, y);
			// data available

			//usleep(100000);    // allow 100ms for client pipes to send the entire command
	
			// check sink sockets  
			//  this is only for IR RX, TX/stat ack will be handled directly via blocking operations
			//       inside of the process_uart for that command 
			for (i=0;i<MAX_SINK;i++){
                        if ((serial_sock[i]>0) && poll_ret(serial_sock[i], max_set, poll_list)){
				// IRX protocol
				//   pulse-msb pulse-lsb blank-msb blank-lsb  .....
				//     ends with timeout 0x04 00

				//  for RX forward we would convert to hex and send to connected sockets
				//  QSIRPULSE000 hexcode \cr

				//  no need for HID or Cloud decode on this driver
				
				//  for IRUSB motion, it is either ON or OFF

				serial_len[i] = read(serial_sock[i],&serial_buf[i][serial_wp[i]],256);
				if (serial_len[i]<1){
                                        close(serial_sock[i]);
                                        serial_sock[i] = 0;
                                        printf("Serial socket %d returned %d errno %d\n",i,serial_len[i],errno);
                                        printf("Closing serial socket %d\n",i);
                                        syslog(LOG_INFO,"Closing serial socket %d\n",i);

					// this is an ERROR, restart_app
					restart_app++;

				}else {
					printf("Read %d\n",serial_len[i]);
					int rr;

					for (rr=0;rr<serial_len[i];rr++){
						printf("%02x ",serial_buf[i][serial_wp[i]+rr]);
					}
					printf("\n");
					
					serial_wp[i] += serial_len[i];
					if (serial_wp[i]>1023){
						memcpy(&serial_buf[i][0],&serial_buf[i][1024],serial_wp[i]-1024);
                                        	serial_wp[i] = serial_wp[i]-1024;
					}

					// now process it
					//  commands all terminated by 0x04 0x00
					if (serial_wp[i]>serial_rp[i]){
						process_len = serial_wp[i]-serial_rp[i];
						memcpy(process_buf,&serial_buf[i][serial_rp[i]],process_len);
					}else{
						process_len = (serial_wp[i]+1024)-serial_rp[i];
                                        	memcpy(process_buf,&serial_buf[i][serial_rp[i]],1024-serial_rp[i]);
                                        	memcpy(&process_buf[1024-serial_rp[i]],serial_buf[i],serial_wp[i]);
					}
					//process_buf[process_len]=0;
					// process loop
                          		processed = 0;
                          		last_processed = 0;
					printf("Buff length %d\n",process_len);
					for(j=1;j<process_len;j++){
                                		if ((process_buf[j]==0x00)&&(process_buf[j-1]==0x04)){
							last_processed=processed;
							processed = j;
							cmd_buf = &process_buf[last_processed];
                                        		cmd_len = j-last_processed+1;
							printf("New code length %d\n",cmd_len);
							process_rxcode(cmd_buf,cmd_len, getDevid(i),serial_rxcnt[i]);
							serial_rxcnt[i]+=10;
						}
					}
					if (processed>0){
						serial_rp[i] = (serial_rp[i]+processed+1)%1024;
					}
				}

			}else{
				serial_rxcnt[i]--;
				if (serial_rxcnt[i]<0){serial_rxcnt[i]=0;}
			}
			}
			

			// check web
			web_len = 0;
                        if ((client_sockfd>0) && poll_ret(client_sockfd, max_set, poll_list)){
				printf("Web client socket active\n");
                                // connected socket
				if (web_wp>1023){
					syslog(LOG_ERR,"Web wp overflow %d!!!",web_wp);
					web_wp=0;
				}
                                web_len = read(client_sockfd, &web_buf[web_wp],256);
                                if (web_len < 1){
                                        // I think this is the proper way to check for closing a socket
                                        close(client_sockfd);
                                        client_sockfd = 0;
                                        printf("Closing web socket\n");
                                        syslog(LOG_INFO,"Closing web socket\n");
                                }else{
                                // echo back (nope)
                                // write(connect_sock,eth_buf,eth_len);
                                // web_buf has command of web_len
					web_wp += web_len;
                                }
				if (web_wp>1023){   // only use 256 of the buffer
					strncpy(&web_buf[0],&web_buf[1024],web_wp-1024);
					web_wp = web_wp-1024;
				}
                        }
			if (server_sockfd>0){
                        if (poll_ret(server_sockfd, max_set, poll_list)){
				printf("Web listen socket active\n");
                                // listen socket
				client_len = sizeof(client_address);
                                client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &client_len);
                                printf("Accepted new web connection \n");
                                syslog(LOG_INFO,"Accepted new web connection \n");
                        }
			}

			// ethernet connect sockets
			for (i=0;i<48;i++){
			eth_len[i]=0;
			if ((connect_sock[i]>0) && poll_ret(connect_sock[i], max_set, poll_list)){
				//printf("Ethernet connect socket %d active\n",i);
				// connected socket
				if (eth_wp[i]>1023){
					syslog(LOG_ERR,"Eth wp overflow %d %d!!!",i, eth_wp[i]);
					eth_wp[i]=0;
				}
				eth_len[i] = read(connect_sock[i],&eth_buf[i][eth_wp[i]],256);
				if (eth_len[i] < 1){
					// I think this is the proper way to check for closing a Tcp socket
					close(connect_sock[i]);
					connect_sock[i] = 0;
					printf("Closing TCP socket\n");
					syslog(LOG_INFO,"Closing TCP socket %d\n",i);
				}else{
					// echo back
					//write(connect_sock,eth_buf,eth_len);
					// eth_buf has command of eth_len
					eth_wp[i] += eth_len[i];
					if (eth_len[i]<255){eth_q[i]=0;}
				}
				if (eth_wp[i]>1023){   // only use 256 of the buffer
					strncpy(&eth_buf[i][0],&eth_buf[i][1024],eth_wp[i]-1024);
					eth_wp[i] = eth_wp[i]-1024;
				}
			}else{eth_q[i]=0;}
			}
			// check ethernet listen (after connect since could close those)
			if (sock>0){
			if (poll_ret(sock, max_set, poll_list)){
				printf("Ethernet listen socket active\n");
				syslog(LOG_INFO,"Ethernet listen socket active\n");
				// find first free socket
                                y=255;
                                for (i=0;i<48;i++){
                                        if (connect_sock[i]==0){
                                                y = i;
                                                i=50;
                                        }
                                }
                                // if all connection opens, close it  (STOMP behavior, prevent lockout)
				//  FIFO stomp behavior would be better, but sockets are not in order of time...
				if (y==255){
                                        close(connect_sock[47]);
                                        connect_sock[47] = 0;
                                        printf("Stomping open TCP socket\n");
                                        syslog(LOG_INFO,"Stomping open TCP socket\n");
                                        y=47;
                                }

				// listen socket
				len=sizeof(serv_name);
				connect_sock[y] = accept(sock, (struct sockaddr *)&serv_name, &len);
				inet_ntop(AF_INET, &serv_name.sin_addr, eth_buf[y], 64);
				printf("Accepted new TCP connection %d %s\n",y, eth_buf[y]);
				syslog(LOG_INFO,"Accepted new TCP connection %d %s\n", y, eth_buf[y]);
				eth_wp[y]=0;
                                eth_rp[y]=0;
			}
			}

			// firebase socket
                        fb_len=0;
                        if ((fdr_fb[0]>0) && poll_ret(fdr_fb[0], max_set, poll_list)){
                                fb_len = read(fdr_fb[0], &fb_buf[fb_wp],256);
                                if (fb_len < 1){
                                        syslog(LOG_INFO,"Closing FIREBASE socket \n");
                                        // I think this is the proper way to check for closing a socket
                                        close(fdr_fb[0]);
                                        fdr_fb[0] = 0;
                                }
                                else{
                                        fb_wp += fb_len;
                                }
                                if (fb_wp>1023){   // only use 256 of the buffer
                                        strncpy(&fb_buf[0],&fb_buf[1024],fb_wp-1024);
                                        fb_wp = fb_wp-1024;
                                }
                        }

		 	// process any commands  (all above use same rs232 command sequences)
			for (i=0;i<50;i++){   
			  if (i<48){
				if (eth_wp[i]>=eth_rp[i]){
					process_len = eth_wp[i]-eth_rp[i];
					strncpy(process_buf,&eth_buf[i][eth_rp[i]],process_len);
				}else{
					process_len = (eth_wp[i]+1024)-eth_rp[i];
					strncpy(process_buf,&eth_buf[i][eth_rp[i]],1024-eth_rp[i]);
					strncpy(&process_buf[1024-eth_rp[i]],eth_buf[i],eth_wp[i]);
				}
			  }else if (i==48){
				if (web_wp>=web_rp){
					process_len = web_wp-web_rp;
					strncpy(process_buf,&web_buf[web_rp],process_len);
				}else{
					process_len = (web_wp+1024)-web_rp;
					strncpy(process_buf,&web_buf[web_rp],1024-web_rp);
					strncpy(&process_buf[1024-web_rp],web_buf,web_wp);
				}
                          }else if (i==49){
                                if (fb_wp>=fb_rp){
                                        process_len = fb_wp-fb_rp;
                                        strncpy(process_buf,&fb_buf[fb_rp],process_len);
                                }else{
                                        process_len = (fb_wp+1024)-fb_rp;
                                        strncpy(process_buf,&fb_buf[fb_rp],1024-fb_rp);
                                        strncpy(&process_buf[1024-fb_rp],fb_buf,fb_wp);
                                }
                          }
			  if (process_len>1290){
				syslog(LOG_ERR,"Process len too long %d, corruption!",process_len);
			  }

			  // process loop
			  processed = 0;
			  last_processed = 0;

			  // From eth/web   if our command, execute and send echo OK

		          for(j=1;j<process_len;j++){
				if (process_buf[j]==0xd){
					// hit cr
					last_processed=processed;
					processed = j;
					cmd_buf = &process_buf[last_processed];
					cmd_len = j-last_processed;
					// need to chomp any nulls or LF at beginning
					while((cmd_len>0)&&(cmd_buf[0]<33)){
						cmd_buf++;
						cmd_len--;
					}
					// ok, process it!
					if (cmd_len>1023){
						syslog(LOG_ERR,"Cmd_len too long %d",cmd_len);

					}else{
					strncpy(sbuffer,cmd_buf,cmd_len);
					sbuffer[cmd_len]=0;
					printf("Cmd_len %d cmd:%s\n",cmd_len,sbuffer);
					if (!(strstr(sbuffer,"QSTAT"))){
						// suppress meta log
						syslog(LOG_INFO,"Cmd_len %d cmd:%s\n",cmd_len,sbuffer);
					}
					if (i<48){  //eth
						if (process_uartstr(cmd_buf, cmd_len, connect_sock[i],eth_q[i])){
							//write(connect_sock,ret_buf, strlen(ret_buf));
						}
						eth_q[i]++;
					}else if (i==48){ //web
						if (process_uartstr(cmd_buf, cmd_len, client_sockfd,0)){
							//write(client_sockfd,ret_buf, strlen(ret_buf));
						}
					}else if (i==49){ //firebase
                                                if (process_uartstr(cmd_buf, cmd_len, fds_fb[1],0)){
                                                        //write(fds_fb[1],ret_buf, strlen(ret_buf));
                                                }
                                        }
					// done, goto next
					}
				}
			  }

			  // end processing
			  if (i<48){eth_rp[i] = (eth_rp[i]+processed)%1024;}
			  else if (i==48){web_rp = (web_rp+processed)%1024;}
			  else if (i==49){fb_rp = (fb_rp+processed)%1024;}

			}

			// gc connect sockets
			for (i=0;i<48;i++){
			gc_len[i]=0;
			if ((gcconnect_sock[i]>0) && poll_ret(gcconnect_sock[i], max_set, poll_list)){
				//printf("Ethernet connect socket %d active\n",i);
				// connected socket
				if (gc_wp[i]>1023){
					syslog(LOG_ERR,"GC wp overflow %d %d!!!",i, gc_wp[i]);
					gc_wp[i]=0;
				}
				gc_len[i] = read(gcconnect_sock[i],&gc_buf[i][gc_wp[i]],256);
				if (gc_len[i] < 1){
					// I think this is the proper way to check for closing a Tcp socket
					close(gcconnect_sock[i]);
					gcconnect_sock[i] = 0;
					printf("Closing GC socket\n");
					syslog(LOG_INFO,"Closing GC socket %d\n",i);
				}else{
					// echo back
					//write(connect_sock,eth_buf,eth_len);
					// eth_buf has command of eth_len
					gc_wp[i] += gc_len[i];
					if (gc_len[i]<255){gc_q[i]=0;}
				}
				if (gc_wp[i]>1023){   // only use 256 of the buffer
					strncpy(&gc_buf[i][0],&gc_buf[i][1024],gc_wp[i]-1024);
					gc_wp[i] = gc_wp[i]-1024;
				}
			}else{gc_q[i]=0;}
			}
			// check ethernet listen (after connect since could close those)
			if (gcsock>0){
			if (poll_ret(gcsock, max_set, poll_list)){
				printf("GC listen socket active\n");
				syslog(LOG_INFO,"GC listen socket active\n");
				// find first free socket
                                y=255;
                                for (i=0;i<48;i++){
                                        if (gcconnect_sock[i]==0){
                                                y = i;
                                                i=50;
                                        }
                                }
                                // if all connection opens, close it  (STOMP behavior, prevent lockout)
				//  FIFO stomp behavior would be better, but sockets are not in order of time...
				if (y==255){
                                        close(gcconnect_sock[47]);
                                        gcconnect_sock[47] = 0;
                                        printf("Stomping open TCP socket\n");
                                        syslog(LOG_INFO,"Stomping open TCP socket\n");
                                        y=47;
                                }

				// listen socket
				gclen=sizeof(gcserv_name);
				gcconnect_sock[y] = accept(gcsock, (struct sockaddr *)&gcserv_name, &gclen);
				inet_ntop(AF_INET, &gcserv_name.sin_addr, gc_buf[y], 64);
				printf("Accepted new GC connection %d %s\n",y, gc_buf[y]);
				syslog(LOG_INFO,"Accepted new GC connection %d %s\n", y, gc_buf[y]);
				gc_wp[y]=0;
                                gc_rp[y]=0;
			}
			}

		 	// process any GC commands
			for (i=0;i<48;i++){   
				if (gc_wp[i]>=gc_rp[i]){
					process_len = gc_wp[i]-gc_rp[i];
					strncpy(process_buf,&gc_buf[i][gc_rp[i]],process_len);
				}else{
					process_len = (gc_wp[i]+1024)-gc_rp[i];
					strncpy(process_buf,&gc_buf[i][gc_rp[i]],1024-gc_rp[i]);
					strncpy(&process_buf[1024-gc_rp[i]],gc_buf[i],gc_wp[i]);
				}

			  if (process_len>1290){
				syslog(LOG_ERR,"Process len too long %d, corruption!",process_len);
			  }

			  // process loop
			  processed = 0;
			  last_processed = 0;

		          for(j=1;j<process_len;j++){
				if (process_buf[j]==0xd){
					// hit cr
					last_processed=processed;
					processed = j;
					cmd_buf = &process_buf[last_processed];
					cmd_len = j-last_processed;
					// need to chomp any nulls or LF at beginning
					while((cmd_len>0)&&(cmd_buf[0]<33)){
						cmd_buf++;
						cmd_len--;
					}
					// ok, process it!
					if (cmd_len>1023){
						syslog(LOG_ERR,"Cmd_len too long %d",cmd_len);

					}else{
					strncpy(sbuffer,cmd_buf,cmd_len);
					sbuffer[cmd_len]=0;
					printf("Cmd_len %d cmd:%s\n",cmd_len,sbuffer);
					if (!(strstr(sbuffer,"QSTAT"))){
						// suppress meta log
						syslog(LOG_INFO,"Cmd_len %d cmd:%s\n",cmd_len,sbuffer);
					}
					process_gcstr(cmd_buf, cmd_len, gcconnect_sock[i-0],gc_q[i]);
					gc_q[i]++;
					}
					// done, goto next
				}
			  }

			  // end processing
			  gc_rp[i] = (gc_rp[i]+processed)%1024;

			}


		} else {
			// select timeout
			for (i=0;i<48;i++){
				eth_q[i]=0;
				gc_q[i]=0;
			}
		}
		// timers

		#ifdef INC_FB
		// fb restart 
    		if (start_fb_timer>=0){
    			start_fb_timer-=delta_sec;
    			if (start_fb_timer<0){
				start_firebase();  // 5 min delay in case it always fails
			}
		}
		#endif

		// vssd
    		vssd_timer-=delta_sec;
    		if (vssd_timer<0){
        		// send data
        		// Only send if we have connected devices
			j=0;
			for (i=0;i<MAX_SINK;i++){
				if (serial_sock[i]>0){j++;}
        		}
			if (j>0){
                		j = openSsdpSendSocket();
                		if (j>=0){sendPacket("NOTIFY",muuid,infname,9093,0);}
                		closeSsdpSendSocket();
			}
        	vssd_timer = 300;  // 5 min
		}

		// gc 
    		gc_timer-=delta_sec;
    		if (gc_timer<0){
        		// send data
        		// Only send if we have connected devices
			j=0;
			for (i=0;i<MAX_SINK;i++){
				if (serial_sock[i]>0){j++;}
        		}
			if (j>0){
                		j = openGCSendSocket();
				if (j>=0){sendGCPacket(gcuuid,infname);}
                		closeGCSendSocket();
			}
        	gc_timer = 50;  // 50 sec
		}

		// init
		if (powerup_init>0){
			// read devid, version from all devices
			printf("Running init\n");
			syslog(LOG_INFO,"Running init");
			write_status(0);
			powerup_init=0;
		}

		// poll timer
    		poll_timer-=delta_sec;
		if (poll_timer<0){
			// read devid, version from all devices
			printf("Running poll\n");
			syslog(LOG_INFO,"Running poll");
			write_status(0);
			poll_timer = 240;  // 4 min
		}

		
	}



	// will reach if restart_app set
	close(sock);
	close(gcsock);
	for(i=0;i<48;i++){
	if(connect_sock[i]>0){close(connect_sock[i]);}
	if(gcconnect_sock[i]>0){close(gcconnect_sock[i]);}
	}
	for(i=0;i<MAX_SINK;i++){
	if(serial_sock[i]>0){
		set_defaultmode(serial_sock[i]);
		close(serial_sock[i]);
		serial_sock[i]=0;
	}
	}
	if (client_sockfd>0){close(client_sockfd);}
	if (server_sockfd>0){close(server_sockfd);}
	if (fb_pid>0){
		kill(fb_pid,SIGINT);
	}
	fprintf(stderr,"IRUSB restarting!\n");
	syslog(LOG_INFO,"IRUSB restarting!\n");
	return 0;
}

int main(int argc, char **argv){
	
	int keep_running;
	int verb = 0;

//======================  arguments  ===============================================
	char *arg;
	//int noadi=1;

	if (argc>1){
		while ((arg = *++argv)){
			if (!strcasecmp(arg,"v")){
				verb=1;
			}
		}
	}

//======================  run  ===============================================
	
	keep_running=1;
	while (keep_running>0){
		mainloop(verb);
		sleep(3);
	}
	return 0;
}



