

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <poll.h>
#ifdef INC_FB
#include <libxml/parser.h>
#endif
#include <math.h>

#include "process_uartstr.h"
#include "globals.h"

extern int serial_sock[MAX_SINK];  // connected socket
extern int restart_app;
extern int webcapture;
extern pid_t fb_pid;

// globals just for this file
char lastircode[8196];
const char vers_string[32] = "IRUSB 2.0";

typedef struct {
	int TXCnt;
	int RXCnt;
	char vers[16];
	char devid[16];
	int motion;
} sink_stat_t;

sink_stat_t sink_stat[MAX_SINK];

char * getDevid(int i){

	return sink_stat[i].devid;
}



int getdec(char * buf, int len){
        int res=0;
        int mlt=1;
        int i;

        for(i=1;i<=len;i++){
                res = res + (buf[len-i]-'0')*(mlt);
                mlt = mlt*10;
        }
        return res;
}

int strpos(char *haystack, char *needle, int nth)
{
    char *res = haystack;
    int i;
    for(i = 1; i <= nth; i++)
    {
        res = strstr(res, needle);
        if (!res)
            return -1;
        else if(i != nth)
            res++;
    }
    return res - haystack;
}

// firebase ---------------------------------------------------------------

int run_python(char *cmds){
  FILE *fp;
  char path[512];
  int retval=0;

  syslog(LOG_INFO,"Running %s",cmds);
  /* Open the command for reading. */
/*
  fp = popen(cmds, "r");
*/
  strcat(cmds," >/tmp/fb_out");
  system(cmds);
  fp = fopen("/tmp/fb_out","r");
  if (fp == NULL) {
    syslog(LOG_ERR,"Could not exec file");
    return 0;
  }

  /* Read the output a line at a time - output it. */
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
        if (strstr(path,"Success")){
                retval=1;
        }
        syslog(LOG_INFO,"Read %s",path);
  }

  /* close */
  pclose(fp);
  return retval;
}


int read_fbcreds(char *fbun, char *fbpw){
        struct stat statb;
        int fben=0;
        if (stat("../../data/vm_firebase.txt",&statb)==0){
                FILE *fbfp;

                fbun[0]=0;
                fbpw[0]=0;
                fbfp = fopen("../../data/vm_firebase.txt","r");
                if (fbfp && !feof(fbfp) && !ferror(fbfp)){
                        fscanf(fbfp,"%d %s %s\n",&fben,fbun,fbpw);
                }
                if (fbfp){fclose(fbfp);}
        }
        return fben;
}

int check_fbcreds(void){
        char fbun[256];
        char fbpw[256];
        char cmds[256];
        int retval=0;
        read_fbcreds(fbun,fbpw);
        if ((strlen(fbun)>3)&&(strlen(fbpw)>3)){
                sprintf(cmds,"../../python/test_account.py %s %s",fbun,fbpw);
                retval = run_python(cmds);
        }
        return retval;
}

int create_fbcreds(void){
        char fbun[256];
        char fbpw[256];
        char cmds[256];
        int retval=0;
        read_fbcreds(fbun,fbpw);
        if ((strlen(fbun)>3)&&(strlen(fbpw)>3)){
                sprintf(cmds,"../../python/create_account.py %s %s",fbun,fbpw);
                retval = run_python(cmds);
        }
        return retval;
}

int email_fbcreds(void){
        char fbun[256];
        char fbpw[256];
        char cmds[256];
        int retval=0;
        read_fbcreds(fbun,fbpw);
        if ((strlen(fbun)>3)){
                sprintf(cmds,"./send_email.py %s %s",fbun,fbpw);
                retval = run_python(cmds);
        }
        return retval;
}

int reset_fbcreds(void){
        char fbun[256];
        char fbpw[256];
        char cmds[256];
        int retval=0;
        read_fbcreds(fbun,fbpw);
        if ((strlen(fbun)>3)){
                sprintf(cmds,"../../python/reset_passw.py %s",fbun);
                retval = run_python(cmds);
        }
        return retval;
}
// db ir code parseing---------------------------------------------------------------

void exec_eth(char *url, int url_len){
        //  either call ethcontrol or curl
        //  url_len could be up to 8196
        char cmdline[8324];
        if ((strncmp(url,"wol",3)==0)&&(strncmp(url,"tcp",3)==0)){
                // ethcontrol
                sprintf(cmdline,"./ethcontrol ");
                strncpy(&cmdline[13],url,url_len);
                cmdline[url_len+14] = 0;
        }else{
                // curl
                sprintf(cmdline,"curl ");
                strncpy(&cmdline[5],url,url_len);
                cmdline[url_len+6] = 0;
        }
        //   non blocking fork/exec
        strcat(cmdline, " &");
        syslog(LOG_INFO,"ETH command %s",cmdline);
        system(cmdline);
}

void replace_char(char *s, char find, char replace){
        int i;
        for(i=0;i<strlen(s);i++){
                if (s[i] == find){s[i]=replace;}
        }
}

#ifdef INC_FB
int getrxname(int typ, int tnum, char *nam){

	xmlDoc *tdoc;
	xmlNode *root, *child, *node, *schild, *snode;
	int num;
	xmlChar *key;
	
	if (typ == 0){
		tdoc = xmlReadFile("../../data/srcdefs.xml",NULL,0);
	}else{
		tdoc = xmlReadFile("../../data/sinkdefs.xml",NULL,0);
	}
	root = xmlDocGetRootElement(tdoc);
	child = root->children;  // first child
	for (node = child; node; node = node->next){  // loop all at 1st level
		// get name & number
		schild = node->children;  // first child
		num = -1;
		nam[0]=0;
		for (snode = schild; snode; snode = snode->next){  // loop all at 1st level
			key = xmlNodeListGetString(tdoc,snode->xmlChildrenNode,1);
			//syslog(LOG_INFO,"Name %s",key);
			if ((!xmlStrcmp(snode->name, (const xmlChar *)"name"))){
				strcpy(nam,(char *)key);			
			}else if ((!xmlStrcmp(snode->name, (const xmlChar *)"number"))){
				num = atoi((char *)key);
			}
			xmlFree(key);
			if ((num>=0)&&(strlen(nam)>0)){
				if (num==tnum){return 1;}
			}
		}
	}
	xmlFreeDoc(tdoc);
	nam[0]=0;
	return -1;
}

int find_rxcode(char *devid, char *buf, char *rbuf){
        // buf is the QSIRPULSE command captured
	//  if devid = null, match any device.  Else on devid device

	// return 1 on found, else -1

	xmlDoc *tdoc;
	xmlNode *root, *child, *node, *schild, *snode, *dchild, *dnode;
	int num,typ,mf,i;
	xmlChar *key;

	char nbuf[256];
        char jbuff[9216];
	int devtype;
        int matchdev;
        int matchnum;

	devtype=0;
	// cmd code skip  "QSIRPULSE000 ", start at [13]
	// first parse our captured code
	int intarr[2048];
	int * intarr2;
	int arridx = 0;
	float per = 0.0;
	float per2 = 0.0;
	int sum = 0;
	int intarrm[2048];
        int * intarrm2;
        int arridxm = 0;
	intarr2 = parse_hex(&buf[13], &per, intarr, &arridx, &sum);
	if ((sum<4)||(intarr2==NULL)){
                printf("Invalid code\n");
                syslog(LOG_ERR,"Invalid hex code");
                return -1;
        }

	tdoc = xmlReadFile("../../data/rxcodes.xml",NULL,0);
	root = xmlDocGetRootElement(tdoc);
	child = root->children;  // first child
	matchdev=-1;
	matchnum=-1;
	jbuff[0]=0;
	rbuf[0]=0;
	nbuf[0]=0;
	for (node = child; node; node = node->next){  // loop all at 1st level   (root)
  	  dchild = node->children;  // first child
	  for (dnode = dchild; dnode; dnode = dnode->next){  // loop all at 1st level   (Device => devid, etc, Codes)
		// get name & number
		if ((!xmlStrcmp(dnode->name, (const xmlChar *)"devid"))){
			key = xmlNodeListGetString(tdoc,dnode->xmlChildrenNode,1);
			if ((strlen(devid)<1)||(strcasecmp(devid,(char *)key)==0)){
				matchdev=1;
			}
			xmlFree(key);
		}else if ((!xmlStrcmp(dnode->name, (const xmlChar *)"devtype"))){
			key = xmlNodeListGetString(tdoc,dnode->xmlChildrenNode,1);
			devtype = atoi((char *)key);
			xmlFree(key);
		}else if ((matchnum<0)&&(!xmlStrcmp(dnode->name, (const xmlChar *)"Codes"))){  
		  schild = dnode->children;  // first child
		  num=-1;
		  typ=-1;
		  jbuff[0]=0;
		  for (snode = schild; snode; snode = snode->next){  // loop on Codes => values
			key = xmlNodeListGetString(tdoc,snode->xmlChildrenNode,1);
			if ((!xmlStrcmp(snode->name, (const xmlChar *)"type"))){
				typ = atoi((char *)key);
			}else if ((!xmlStrcmp(snode->name, (const xmlChar *)"number"))){
				num = atoi((char *)key);
			}else if ((!xmlStrcmp(snode->name, (const xmlChar *)"data"))){
				strcpy(jbuff,(char *)key);			
			}
			if ((num>=0)&&(typ==0)&&(strlen(jbuff)>0)){
				mf = 1;
				// now compare code to see if match
				//   read freq and correct by it
				//   captured code must be at least as long as saved code (once code or repeat code)
				//   ignore first burst pair and last burst pair
				//   
				//    values in range of 110 - 330
				replace_char(jbuff,'_',' ');
				intarrm2 = parse_hex(jbuff, &per2, intarrm, &arridxm, &sum);
				//syslog(LOG_INFO,"Check against code %d, length %d verses length %d",num,arridxm,arridx);
				if ((sum>4)&&(arridxm>=arridx)&&(intarrm2!=NULL)){
					for(i=2;i<arridx-2;i++){
						int th = floor( (float)intarr2[i] * ((1-per2/per)));
						int cv = intarr2[i]+th;
						if (((cv + cv/4)<intarrm2[i])||((cv - cv/4)>intarrm2[i])){
							//syslog(LOG_INFO,"Fail on idx %d %d vrs %d cv %d",i,intarrm2[i],intarr2[i],cv);
							mf=0;
							i=4000;
						}
					}
				}else{mf=0;}

				if (mf>0){
					// match, keep jbuf
					syslog(LOG_INFO,"Matched code %d devtype %d",num,devtype);
					matchnum=num;
                  			jbuff[0]=0;
				}else{
					num=-1;
                  			typ=-1;
                  			jbuff[0]=0;
				}
			}
			xmlFree(key);
		  }
		}
		if ((matchdev>0)&&(matchnum>=0)){
			// now get code name and return it
			i = getrxname(devtype,num, nbuf);
			xmlFreeDoc(tdoc);
			if (i>0){
				sprintf(rbuf,"QSIRNCODE %s\r",nbuf);
				return 1;
			}
			return -1;
		}
	  }
	}
	xmlFreeDoc(tdoc);

        return -1;
}

int gethexcode(int is_src,char *devid, int codenum, int *codetype, char *buf){
        // buf should not exceed 990 chars
        //  called only from forward_src or forward_cmd (sink)
        // return chars written
        //    codenum is 0->47
	xmlDoc *tdoc;
	xmlNode *root, *child, *node, *schild, *snode, *dchild, *dnode;
	int num,typ;
	xmlChar *key;

        char jbuff[9216];
        int matchdev;
        int matchnum;

	// if devid not set, find first matching code

	tdoc = xmlReadFile("../../data/txcodes.xml",NULL,0);
	root = xmlDocGetRootElement(tdoc);
	child = root->children;  // first child
	matchdev=-1;
	matchnum=-1;
	jbuff[0]=0;
	*codetype=0;
	for (node = child; node; node = node->next){  // loop all at 1st level   (root)
  	  dchild = node->children;  // first child
	  for (dnode = dchild; dnode; dnode = dnode->next){  // loop all at 1st level   (Device => devid, etc, Codes)
		// get name & number
		if ((!xmlStrcmp(dnode->name, (const xmlChar *)"devid"))){
			key = xmlNodeListGetString(tdoc,dnode->xmlChildrenNode,1);
			if ((strlen(devid)<1)||(strcasecmp(devid,(char *)key)==0)){
				matchdev=1;
			}
			xmlFree(key);
		}else if ((matchnum<0)&&(!xmlStrcmp(dnode->name, (const xmlChar *)"Codes"))){  
		  schild = dnode->children;  // first child
		  num=-1;
		  typ=-1;
		  jbuff[0]=0;
		  for (snode = schild; snode; snode = snode->next){  // loop on Codes => values
			key = xmlNodeListGetString(tdoc,snode->xmlChildrenNode,1);
			if ((!xmlStrcmp(snode->name, (const xmlChar *)"type"))){
				typ = atoi((char *)key);
			}else if ((!xmlStrcmp(snode->name, (const xmlChar *)"number"))){
				num = atoi((char *)key);
			}else if ((!xmlStrcmp(snode->name, (const xmlChar *)"data"))){
				strcpy(jbuff,(char *)key);			
			}
			if ((num>=0)&&(typ>=0)&&(strlen(jbuff)>0)){
				if (num==codenum){
					// match, keep jbuf
					matchnum=1;
				}else{
					num=-1;
                  			typ=-1;
                  			jbuff[0]=0;
				}
			}
			xmlFree(key);
		  }
		}
		if ((matchdev>0)&&(matchnum>0)&&(strlen(jbuff)>0)){
			// process and return val
			*codetype = typ;
			if (*codetype==0){
				replace_char(jbuff,'_',' ');
			}
			xmlFreeDoc(tdoc);
			if (strlen(jbuff)<991){
				strcpy(buf,jbuff);
				return strlen(jbuff);
			}
			return 0;
		}
	  }
	}
	xmlFreeDoc(tdoc);

        return 0;
}

int getcode(char *cname){
	int retval = -1;

	xmlDoc *tdoc;
	xmlNode *root, *child, *node, *schild, *snode;
	int num;
	char nam[256];
	xmlChar *key;
	
	tdoc = xmlReadFile("../../data/srcdefs.xml",NULL,0);
	root = xmlDocGetRootElement(tdoc);
	child = root->children;  // first child
	for (node = child; node; node = node->next){  // loop all at 1st level
		// get name & number
		schild = node->children;  // first child
		num = -1;
		nam[0]=0;
		for (snode = schild; snode; snode = snode->next){  // loop all at 1st level
			key = xmlNodeListGetString(tdoc,snode->xmlChildrenNode,1);
			//syslog(LOG_INFO,"Name %s",key);
			if ((!xmlStrcmp(snode->name, (const xmlChar *)"name"))){
				strcpy(nam,(char *)key);			
			}else if ((!xmlStrcmp(snode->name, (const xmlChar *)"number"))){
				num = atoi((char *)key);
			}
			xmlFree(key);
			if ((num>=0)&&(strlen(nam)>0)){
				if (strcasecmp(cname,nam)==0){retval = num;} //check it
			}
		}
	}
	xmlFreeDoc(tdoc);

	if (retval<0){
		// try sinkdefs
	tdoc = xmlReadFile("../../data/sinkdefs.xml",NULL,0);
	root = xmlDocGetRootElement(tdoc);
	child = root->children;  // first child
	for (node = child; node; node = node->next){  // loop all at 1st level
		// get name & number
		schild = node->children;  // first child
		num = -1;
		nam[0]=0;
		for (snode = schild; snode; snode = snode->next){  // loop all at 1st level
			key = xmlNodeListGetString(tdoc,snode->xmlChildrenNode,1);
			if ((!xmlStrcmp(snode->name, (const xmlChar *)"name"))){
				strcpy(nam,(char *)key);			
			}else if ((!xmlStrcmp(snode->name, (const xmlChar *)"number"))){
				num = atoi((char *)key);
			}
			xmlFree(key);
			if ((num>=0)&&(strlen(nam)>0)){
				if (strcasecmp(cname,nam)==0){retval = num + 1024;} //check it
			}
		}
	}
	xmlFreeDoc(tdoc);

	}

	return retval;
}

void ircode_cmd(char *process_buf,int process_len,int socket_fp,int outp_start, int queued){
	char newcmd[2048];
	char xbuf[2048];
	int codetype,codenum,issrc,j;
	char devid[12];

        codetype=-1;
	devid[0]=0;
        codenum = getdec(&process_buf[outp_start],3);
	if (process_buf[2]=='D'){issrc=0;}
	else{issrc=1;}
	strncpy(newcmd,process_buf,process_len);
	newcmd[process_len]=0;
	if (strstr(newcmd,"ID=")){
		strncpy(devid,strstr(newcmd,"ID=")+3,8);
		devid[8]=0;
	}else if(strstr(newcmd,"id=")){
                strncpy(devid,strstr(newcmd,"id=")+3,8);
                devid[8]=0;
	}
	newcmd[0]=0;
	xbuf[0]=0;
        j = gethexcode(issrc,devid,codenum,&codetype,xbuf);
	//syslog(LOG_INFO,"DB code %d for dev %s is type %d length %d %s",codenum,devid,codetype,j,xbuf);
	syslog(LOG_INFO,"DB code %d for dev %s is type %d length %d",codenum,devid,codetype,j);
        if (codetype==2){
              // ETH
              if (xbuf!=NULL){exec_eth(xbuf, strlen(xbuf));}
        }else{
              //ir
              sprintf(newcmd,"QSIRPULSE ");
              // send R and IR code (with space end)
              if (process_len > (outp_start+4)){
               strncat(newcmd,&process_buf[outp_start+4],process_len-(outp_start+4));
               strcat(newcmd," ");
              }else {strcat(newcmd,"R=01 ");}
              strncat(newcmd,xbuf,j);
              newcmd[strlen(newcmd)+1]=0;
              newcmd[strlen(newcmd)]=13;
	}
	
	// check if dup command then execute
	if (strlen(newcmd)>20){
		//syslog(LOG_INFO,"CMD: %s",newcmd);
		if ((queued>0)&&(strncmp(lastircode,&newcmd[10],strlen(newcmd)-10)==0)){
			syslog(LOG_INFO,"Queued command ignored %d",queued);
		}else{
			// this command will be BLOCKING
			run_ircode(&newcmd[10], strlen(newcmd)-10, -1);
		}
		strncpy(lastircode,&newcmd[10],strlen(newcmd)-10);
		lastircode[strlen(newcmd)-10]=0;
	}
}

void ircoden_cmd(char *process_buf,int process_len,int socket_fp,int outp_start, int queued){
	// get name and convert to code
	char newcmd[2048];
	char r[256];
	char i[256];
	char s[256];
	r[0]=0;
	i[0]=0;
	s[0]=0;
	int n;
	if (process_len>11){
		strncpy(newcmd,&process_buf[10],process_len-10);
		newcmd[process_len-10]=0;
		n = sscanf(newcmd,"%s %s %s",r,i,s);
		if (n==2){
			strcpy(s,i);
			i[0]=0;
		}else if (n==1){
			strcpy(s,r);
			r[0]=0;
		}
		if (strlen(s)>0){
			// find code
			n = getcode(s);
			syslog(LOG_INFO, "Code %s maps to %d",s,n);
			if (n>0){
				if (n>1023){
					sprintf(newcmd,"QDIRCODE%03d",n-1024);
				}else{
					sprintf(newcmd,"QSIRCODE%03d",n);
				}
				if (strlen(r)>0){
					strcat(newcmd," ");
					strcat(newcmd,r);
				}
				if (strlen(i)>0){
					strcat(newcmd,i);
				}
              			newcmd[strlen(newcmd)+1]=0;
              			newcmd[strlen(newcmd)]=13;
				ircode_cmd(newcmd,strlen(newcmd),socket_fp,8,queued);
			}
		}	
	}
}
#endif


// hex code parseing---------------------------------------------------------------
int* parse_hextx(char *hexcode, float *per, int *intarr, int *arridx, int *sum){

        // per is timer period (output)
	// intarr is the integer output array (output)  arridx is the number of terms
	//  sum of intarr is the output

        // first hexcode into arraya
        //int intarr[2048];

        char *data = hexcode;
	int offset =0;
	int n = 0;
	int idx = 0;
	//int bp = 0;
        while (1 == sscanf(data, "%x%n", &n, &offset)) {
		if (n>2048){n=2048;}
                else if (n<0){n=0;}
                if (idx<2048){intarr[idx] = n;}
                data += offset;
                idx++;
        }
        if ((idx>10)&&(intarr[0] == 0)&&(intarr[1] > 10)&&(intarr[1] < 10000)&&((intarr[2] > 4)||(intarr[3] > 4))&&(intarr[2]>=0)&&(intarr[3]>=0)) {
                *per = (float)((float)intarr[1] * 0.241)/2000000.0;
                // use repeat if avail, else once

		if ((intarr[3] > 4)){  // use repeat if avail, else once
			*arridx = intarr[3]*4 + intarr[2]*2;  // double repeat code
			if (((intarr[3]*2+4+intarr[2]*2)>idx)||(*arridx>2043)){
				return NULL;
			}
			// copy end of code
			memcpy(&intarr[intarr[3]*2+4+intarr[2]*2],&intarr[4+intarr[2]*2],intarr[3]*2*sizeof(int));
			intarr = (int *)&intarr[4];  // reset pointer start
		}else{	// use once	
			*arridx = intarr[2]*2;
			if ((*arridx+4)>idx){*arridx=idx-4;}  // truncate if too long
			intarr = (int *)&intarr[4];
		}

                // sum all burst pairs
                for (n=0;n<*arridx;n++){
			// all burst pairs are in PERIODS of the carrier, so 2x samples
			intarr[n]=intarr[n]*2;
                        *sum += intarr[n];
                }
                if (*sum < 256){*sum=256;}
                else if (*sum > 64000){*sum=64000;}
                
		// return intarr, arridx, sum
		
                return intarr;
        }else{
                //error, not learned code
                return NULL;
        }
}

//  below is original for TX parsing
int* parse_hex(char *hexcode, float *per, int *intarr, int *arridx, int *sum){

        // per is timer period (output)
	// intarr is the integer output array (output)  arridx is the number of terms
	//  sum of intarr is the output

        // first hexcode into arraya
        //int intarr[2048];

        char *data = hexcode;
	int offset =0;
	int n = 0;
	int idx = 0;
	int bp = 0;
        while (1 == sscanf(data, "%x%n", &n, &offset)) {
		if (n>2048){n=2048;}
                else if (n<0){n=0;}
                if (idx<2048){intarr[idx] = n;}
                data += offset;
                idx++;
        }
        if ((idx>10)&&(intarr[0] == 0)&&(intarr[1] > 10)&&(intarr[1] < 10000)&&((intarr[2] > 4)||(intarr[3] > 4))) {
                *per = (float)((float)intarr[1] * 0.241)/2000000.0;
                // use repeat if avail, else once
                if (intarr[3] > 4){bp = intarr[3];}
                else {bp = intarr[2];}

		if ((intarr[3] > 4) && (intarr[2] > 0)){
			*arridx = bp*2;
			if ((*arridx+4+intarr[2]*2)>idx){*arridx=idx-4-intarr[2]*2;}
			intarr = (int *)&intarr[4+intarr[2]*2];
		}else{		
			intarr = (int *)&intarr[4];
			*arridx = bp*2;
			if ((*arridx+4)>idx){*arridx=idx-4;}
		}

                // sum all burst pairs
                for (n=0;n<*arridx;n++){
			// all burst pairs are in PERIODS of the carrier, so 2x samples
			intarr[n]=intarr[n]*2;
                        *sum += intarr[n];
                }
                if (*sum < 256){*sum=256;}
                else if (*sum > 64000){*sum=64000;}
                
		// return intarr, arridx, sum
		
                return intarr;
        }else{
                //error, not learned code
                return NULL;
        }
}


int readto(int sock, int toms, char *buf, int buflen){

		int y;
		struct pollfd  polll[2];

		polll[0].revents=0;
		polll[0].events = POLLIN | POLLERR | POLLHUP;
		polll[0].fd = sock;
		polll[1].fd = -1;
		polll[1].revents=0;
		polll[1].events = POLLIN | POLLERR | POLLHUP;

		y = poll(polll,1,toms);   // timeout
		if (y<0){ 
			//error
			syslog(LOG_ERR,"Error reading socket %d",sock);
			return -1;
		}else if (y >0){
			// data to read
			y = read(sock,buf,buflen-1);
			if (y<1){syslog(LOG_ERR,"Read returned %d",y);}
			return y;
		}else{
			//timeout
			return 0;
		}
		return 0;
}

void sendhid(int tc, int modcode, int hidcode){
	// write 0x50
	// write hidcode
	//  all devices
	char readbuf[1024];
	int i;

	char modebuf[6];

	modebuf[0]=0x50;
	if (tc == 0x09){
	modebuf[1]=(char)0x83;
	modebuf[2]=(char)0x04;
	modebuf[3]=(char)0x00;
	}else{
	modebuf[1]=(char)tc;
	modebuf[2]=(char)modcode;
	modebuf[3]=(char)hidcode;
	}
	modebuf[4]=0;

	for (i=0;i<MAX_SINK;i++){
	   if (serial_sock[i]>0){
		//flush buffer
		readto(serial_sock[i], 10, readbuf, 1024);

		// set modes
		write(serial_sock[i],modebuf,4);
	   }
	}
}


void send_ircode(int seldev, int repeat, unsigned char *bytearr, int arridx, int save_cd){
	//  sequence
	//    flush read pipe
	//    send "S"   #enter sample mode (so other commands will work)
	//    flush read pipe (data is protocol version)
	//    write 0x26   #Enable transmit handshake
	//    write 0x25   #Enable transmit notify on complete
	//    write 0x24   #Enable transmit byte count report
	//    write 0x3    #enable write mode
	//    flush read pipe   (data should be 0x3E)
	//    loop send bytes 62 at a time
	//        write 62 bytes
	//            read (should be 0x3E)
	//    write last N bytes with 0xff 0xff at end
	//    read (should be 0x3E then "t" 2 bytes of rx count), then "C" for complete
	//    send "S" to go back to sample mode
	//     
	char readbuf[1024];
	int readlen,i;

	// send
	char resetbuf[9];
	resetbuf[0]=0xff;
	resetbuf[1]=0xff;
	resetbuf[2]=0x00;
	resetbuf[3]=0x00;
	resetbuf[4]=0x00;
	resetbuf[5]=0x00;
	resetbuf[6]=0x00;
	resetbuf[7]='S';
	resetbuf[8]=0;
	
	char modebuf[8];
	modebuf[0]=0x26;
	modebuf[1]=0x25;
	modebuf[2]=0x24;
	modebuf[3]=0x03;
	modebuf[4]=0;	

	if (save_cd>=0){

		modebuf[3]=0x60;
		modebuf[4]=(unsigned char)save_cd;
		modebuf[5]=0;
		modebuf[6]=0;
	}

	for (i = 1;i<=repeat;i++){
		// reset
		write(serial_sock[seldev],resetbuf,8);
		usleep(10000);
		//flush buffer
		readlen = readto(serial_sock[seldev], 10, readbuf, 1024);

		// set modes
		if(save_cd>=0){write(serial_sock[seldev],modebuf,6);}
		else{write(serial_sock[seldev],modebuf,4);}
		usleep(10000);
		//get handshake
		readlen = readto(serial_sock[seldev], 250, readbuf, 1024);
		// write loop
		int btosend = arridx*2+2;
		unsigned char *bpnt = bytearr;
		while (btosend>0){
			if ((readlen>0)&&(readlen<1020)&&(readbuf[readlen-1]>0)&&(readbuf[readlen-1]<128)){
				if (readbuf[readlen-1]!=62){syslog(LOG_ERR,"Handshake not 62:%d",readbuf[readlen-1]);}
				if (btosend>readbuf[readlen-1]){
					write(serial_sock[seldev],bpnt,readbuf[readlen-1]);
				}else{
					write(serial_sock[seldev],bpnt,btosend);
				}
				bpnt += readbuf[readlen-1];
				btosend -= readbuf[readlen-1];
				if (btosend<=0){usleep(30000);}  // wait for complete status
				readlen = readto(serial_sock[seldev], 250, readbuf, 1024);
			}else{
				syslog(LOG_ERR,"Failed to handshake write %d",readlen);
				btosend=-1;
			}	
		}
		// check result
		if ((readlen>0)&&(readlen<1020)){
			//readbuf[readlen]=0;
			syslog(LOG_INFO,"Result %d %x %c %x:%x %x:%x %c",readlen,readbuf[0],readbuf[1],readbuf[2],(arridx*2+2)/256,readbuf[3],(arridx*2+2)%256,readbuf[4]);		
		}

		// repeat delay
		if (i<repeat){usleep(100000);}
	}
	syslog(LOG_INFO,"Send complete");

	// set back to RX mode
	// reset
	write(serial_sock[seldev],resetbuf,8);
	usleep(10000);
	//flush buffer
	readlen = readto(serial_sock[seldev], 10, readbuf, 1024);

}

void run_gccode(int dev,int freq,int repeat,int offset, char *buf){

	int intarr[2048];
	unsigned char bytearr[4096];
	int arridx = 0;
	int sum = 0;
	int i,j,v1,v2;
	float valf;
	int vali;

	// make intarr
	char *data = buf;
	int offs;
	int n=0;
	while (1 == sscanf(data, "%d,%n", &n, &offs)) {
                if (n>2048){n=2048;}
                else if (n<0){n=0;}
                if (arridx<2048){intarr[arridx] = n;}
		sum +=n;
                data += offs;
                arridx++;
        }

	float dur =  sum*1000.0/freq;
	syslog(LOG_INFO,"Hex sum is %d, freq %d, symbols %d, duration %f ms, repeat %d\n",sum,freq,arridx,dur,repeat);
	
	// now construct byte array for trans
	for (i=0;i<arridx;i++){
		valf=((float)intarr[i])*46875.0 / (float)freq;
		vali=(int)valf;
		bytearr[2*i]= vali/256;
		bytearr[2*i+1]= vali%256;
	}
	bytearr[arridx*2]=0xff;
	bytearr[arridx*2+1]=0xff;

	int seldev = -1;
	//  sort devices by devid, then select one
	for(i=0;i<MAX_SINK;i++){
		n=0;
		v1=0;
		v2=10;
		if (serial_sock[i]>0){
			sscanf(sink_stat[i].devid,"%x",&v1);
			for(j=0;j<MAX_SINK;j++){
				if (serial_sock[j]>0){
					sscanf(sink_stat[j].devid,"%x",&v2);
					if (v1>v2){n++;}
				}
			}
		}
		if (dev==(n+1)){seldev=n;}
	}

	if ((seldev>=0)&&(serial_sock[seldev]>0)){

		send_ircode(seldev, repeat, bytearr, arridx,-1);

	}
}

void run_ircode(char *buf, int buf_len, int save_cd){
	// 
	//   (id=xxxxxxxx) (r=xx) hex_code
	//  TX format is 
	//      pulse msb, pulse lsb, blank msb, blank lsb, ......  0xff, 0xff
	//        pulses are in 21.33us counts


	int repeat=1;
	char devid[12];
	devid[0]=0;

	// first get ID and repeat code
	if ((strncmp(buf,"id=",3)==0)||(strncmp(buf,"ID=",3)==0)){
		strncpy(devid,&buf[3],8);
		devid[8]=0;
		buf = buf+12;
	}
	if ((strncmp(buf,"r=",2)==0)||(strncmp(buf,"R=",2)==0)){
		repeat = (buf[2]-'0')*10+(buf[3]-'0')*1;
		if (repeat<1){repeat=1;}
		if (repeat>4){repeat=4;}
		buf = buf+5;
	}

	// next parse hex
	
	float per = 0.0;
	int intarr[2048];
	unsigned char bytearr[4096];
	int * intarr2;
	int arridx = 0;
	int sum = 0;
	int i,j;
	float valf;
	int vali;

	intarr2 = parse_hextx(buf, &per, intarr, &arridx, &sum);
	if ((sum<4)||(intarr2==NULL)){
		printf("Invalid code\n");
		syslog(LOG_ERR,"Invalid hex code");
		return;
	}

	float dur = per * sum;
	syslog(LOG_INFO,"Hex sum is %d, period %f us, symbols %d, duration %f ms, repeat %d\n",sum,per*1000000,arridx,dur*1000,repeat);
	
	// now construct byte array for trans

	for (i=0;i<arridx;i++){
		valf=((float)intarr2[i])*per*1.0 / 0.0000213333;
		vali=(int)valf;
		bytearr[2*i]= vali/256;
		bytearr[2*i+1]= vali%256;
	}
	bytearr[arridx*2]=0xff;
	bytearr[arridx*2+1]=0xff;


	// if no devid, send to all
	// now find device to send to
	for (j=0;j<MAX_SINK;j++){

	int seldev = -1;
	if (strlen(devid)>2){
		//search for matching devid
		if ((strlen(devid)<9)&&(strlen(sink_stat[j].devid)>4)&&(strlen(sink_stat[j].devid)<9)){
		if (!strcasecmp(sink_stat[j].devid,devid)){
			seldev=j;
		}}
	}else{
		seldev=j;  // send to all
	}

	if ((seldev>=0)&&(serial_sock[seldev]>0)){

		send_ircode(seldev, repeat, bytearr, arridx, save_cd);

	}
	}
	
}


void run_updatefw(int socket_fp){
	// should have only 1 device attached to update firmware!!
   // for each open device
   //   put into bootloader
   //   update fw
   //   close it
   //   when all are done, reopen all usb devices

	char readbuf[1024];
	char tmpbuf[8];
	int i;
	for (i=0;i<MAX_SINK;i++){
		// close devices
		if (serial_sock[i]>0){
			char resetbuf[9];
			resetbuf[0]=0xff;
			resetbuf[1]=0xff;
			resetbuf[2]=0x00;
			resetbuf[3]=0x00;
			resetbuf[4]=0x00;
			resetbuf[5]=0x00;
			resetbuf[6]=0x00;
			resetbuf[7]=0x00;
			resetbuf[8]=0;
			
			// reset
			write(serial_sock[i],resetbuf,7);
			usleep(10000);
			//flush buffer
			readto(serial_sock[i], 10, readbuf, 1024);

			tmpbuf[0]='$';
			write(serial_sock[i],tmpbuf,1);  //set bootloader mode  (from default mode)
			usleep(10000);
			close(serial_sock[i]);
			usleep(1000000);   // wait for usb to be re-detected
			if (sink_stat[i].vers[1]=='3'){
				system("./fw_update -e -w -v -m flash -vid 0x04d8 -pid 0xe8a6 -ix ./irusb_motion.hex");
			}else{
				system("./fw_update -e -w -v -m flash -vid 0x04d8 -pid 0xf06a -ix ./irusb.hex");
			}
			usleep(100000); 
		}
	}

	sprintf(readbuf,"DONE RESTARTING\r");
	write(socket_fp,readbuf,strlen(readbuf));
	
	// now reopen
	restart_app=1;

}


void set_samplemode(int socket_fp){
			char readbuf[1024];
			char resetbuf[9];
			resetbuf[0]=0xff;
			resetbuf[1]=0xff;
			resetbuf[2]=0x00;
			resetbuf[3]=0x00;
			resetbuf[4]=0x00;
			resetbuf[5]=0x00;
			resetbuf[6]=0x00;
			resetbuf[7]='S';
			resetbuf[8]=0;
			write(socket_fp,resetbuf,8);
			readto(socket_fp, 20, readbuf, 1022);   // flush the version number (10ms)
}

void set_defaultmode(int socket_fp){
			char resetbuf[9];
			resetbuf[0]=0xff;
			resetbuf[1]=0xff;
			resetbuf[2]=0x00;
			resetbuf[3]=0x00;
			resetbuf[4]=0x00;
			resetbuf[5]=0x00;
			resetbuf[6]=0x00;
			resetbuf[7]=0x00;
			resetbuf[8]=0;
			write(socket_fp,resetbuf,8);
}

void write_status(int socket_fp){
	// get version and devid from all connected IRUSB devices, write to socket  (\r term)
	//  write 'V' to get version   Vabc  a=2 b=swh  c=swl     (1.0 is original)
	//    later version will also return IDxxxxxxxx  (32bit id)
	//   if any devid not set also set it now...

	int i;
	char readbuf[1024];
	char tmpbuf[8];
	int readlen;

	for (i=0;i<MAX_SINK;i++){
		if (serial_sock[i]>0){
			char resetbuf[9];
			resetbuf[0]=0xff;
			resetbuf[1]=0xff;
			resetbuf[2]=0x00;
			resetbuf[3]=0x00;
			resetbuf[4]=0x00;
			resetbuf[5]=0x00;
			resetbuf[6]=0x00;
			resetbuf[7]='V';
			resetbuf[8]=0;
			
			syslog(LOG_INFO,"Stat usb %d %d",i,serial_sock[i]);
			// reset
			write(serial_sock[i],resetbuf,7);
			usleep(10000);
			//flush buffer
			readlen = readto(serial_sock[i], 10, readbuf, 1024);

			tmpbuf[0]='V';      // 'V' command only works in IRMan mode, NOT sampling mode
			write(serial_sock[i],tmpbuf,1);
			//usleep(10000);
			readlen = readto(serial_sock[i], 250, readbuf, 1024);

			if ((readlen>0)&&(readlen<1020)){
				readbuf[readlen]=0;
				syslog(LOG_INFO,"Result %s",readbuf);
				if (socket_fp>0){write(socket_fp,readbuf,readlen);}
				tmpbuf[0]='\r';
				if (socket_fp>0){write(socket_fp,tmpbuf,1);}		
				// save to sink_stat
				sink_stat[i].RXCnt=0;
				sink_stat[i].TXCnt=0;
				sink_stat[i].vers[0]=0;
				sink_stat[i].devid[0]=0;
				sink_stat[i].motion=-1;
				sscanf(readbuf,"%6s %8s %d",sink_stat[i].vers,sink_stat[i].devid,&sink_stat[i].motion);
			}
			set_samplemode(serial_sock[i]);  // back to sample mode
	
		}
		//readlen = readto(serial_sock[i], 250, readbuf, 1024);
	}
}

void write_cmd(int socket_fp, char *cmd, int cmdlen, char *devid){

	int i,rp;
	char readbuf[1024];
	char hexo[4];

	for (i=0;i<MAX_SINK;i++){
		// if no devid, send to all
		//  check for devid
		int seldev = -1;
		if (strlen(devid)>2){
		//search for matching devid
		if ((strlen(devid)<9)&&(strlen(sink_stat[i].devid)>4)&&(strlen(sink_stat[i].devid)<9)){
			if (!strcasecmp(sink_stat[i].devid,devid)){
				seldev=i;
			}}
		}else{
			seldev=i;  // send to all
		}
		if ((seldev>=0)&&(serial_sock[seldev]>0)){
			char resetbuf[9];
			resetbuf[0]=0xff;
			resetbuf[1]=0xff;
			resetbuf[2]=0x00;
			resetbuf[3]=0x00;
			resetbuf[4]=0x00;
			resetbuf[5]=0x00;
			resetbuf[6]=0x00;
			resetbuf[7]=0x00;
			resetbuf[8]=0;
			
			syslog(LOG_INFO,"CMD usb %d %d",i,serial_sock[i]);
			// reset
			write(serial_sock[i],resetbuf,7);
			usleep(10000);
			//flush buffer
			readto(serial_sock[i], 10, readbuf, 1024);

			write(serial_sock[i],cmd,cmdlen);
			if (socket_fp>0){
			   usleep(10000);
			   rp = readto(serial_sock[i], 10, readbuf, 1024);
			   for (i=0;i<rp;i++){
				sprintf(hexo,"%02x ",(unsigned char)readbuf[i]);
				write(socket_fp,hexo,4);
			   }
			}
			// else no return value

			set_samplemode(serial_sock[i]);  // back to sample mode
	
		}
	}
}




void echoack(char * process_buf, int process_len, int socket_fp){
	write(socket_fp,process_buf,process_len);
	write(socket_fp,"\rOK\r",4);
}


int process_gcstr (char * process_buf, int process_len, int socket_fp, int queued){

	char line_buf[2048];
	//char line_buf2[2048];
	int i, idx, idc, freq, rcnt, offset;

	// first check for our command
	if (!strncmp(process_buf,"getdevices",10)){
		for(i=0;i<MAX_SINK;i++){if (serial_sock[i]>0){i++;}}
            	sprintf(line_buf,"device,0,0 WIFI\rdevice,1,%d,IR\rendlistdevices\r",i);
	    	write(socket_fp,line_buf,strlen(line_buf));
	}else if (!strncmp(process_buf,"getversion",10)){
		sprintf(line_buf,"version,0,1.0\r");
		write(socket_fp,line_buf,strlen(line_buf));
	}else if (!strncmp(process_buf,"get_NET",7)){
		sprintf(line_buf,"NET,0:1,LOCKED,DHCP,192.168.1.1,255.255.255.0,192.168.1.255\r");
		write(socket_fp,line_buf,strlen(line_buf));
	}else if (!strncmp(process_buf,"get_IR",6)){
            // get_IR,1:#\r    # is IR device number
            // IR,1:#,mode\r
            //   mode is |IR|SENSOR|SENSOR_NOTIFY|IR_BLASTER|LED_LIGHTING|
            //    we only support IR_BLASTER mode...  so we can ignore command and just return the status
            	idx = 1;
		if (strchr(process_buf,':')){
			sscanf(&strchr(process_buf,':')[1],"%d",&idx);
		}
		sprintf(line_buf,"IR,1:%d,IR_BLASTER\r",idx);
		write(socket_fp,line_buf,strlen(line_buf));
	}else if (!strncmp(process_buf,"set_IR",6)){
            // set_IR,1:#\r    # is IR device number
            // not clear if no return or same return as get_IR
	}else if (!strncmp(process_buf,"stopir",6)){
		//stopir,1:#
            // we just echo it back, don't actually stop anything since we don't run in background...
		write(socket_fp,process_buf,process_len);
	}else if (!strncmp(process_buf,"sendir",6)){
		//sendir,1:#,<ID>,<frequency>,<repeat>,<offset>,<on1>,<off1>,<on2>,<off2>,....,<onN>,<offN>\r  (where N is less than 260
            //<ID> is an ASCII number generated by the sender of the sendir command, which is included later in the completeir command to confirm completion of each respective sendir transmission.
            //<frequency> is |15000|15001|....|500000| (in hertz)
            //<repeat> is times to repeat
            // <offset> value indicates the location within the timing pattern to start repeating the IR command as indicated below. The <offset> will always be an odd value since a timing pattern begins with an <on> state and must end with an <off> state.
            // on/off is in number of pulses / periods
            //    IR compressed format assigns the first 15 unique <on><off> pairs capital letters (i.e. A,B,C, etc.) to represent them. In the event that a pair is used in many places inside an IR command, commands can be written with the capital letter in place of the designated pair without being offset by comma
            //    ie  sendir,1:2,2445,40000,1,1,4,5,4,5,8,9,4,5,8,9,8,9
            //    is also  sendir,1:2,2445,40000,1,1,4,5A8,9ABB

            	idx = 1;
		idc = 1;
		freq = 38000;
		rcnt = 1;
		offset = 1;
		if (strchr(process_buf,':')){
			sscanf(&strchr(process_buf,':')[1],"%d",&idx);
		}
		i = strpos(process_buf,",",2);
		if (i>=0){
			sscanf(&process_buf[i+1],"%d",&idc);
		}
		i = strpos(process_buf,",",3);
		if (i>=0){
			sscanf(&process_buf[i+1],"%d",&freq);
			// check for queued code
			if ((queued>0)&&(!strncmp(&process_buf[i+1],lastircode,process_len-i-1))){
				syslog(LOG_INFO,"Queued IR code ignored %d",queued);
			}else{
				strncpy(lastircode,&process_buf[i+1],process_len-i-1);
				lastircode[process_len-i-1]=0;

				i = strpos(process_buf,",",4);
                		if (i>=0){
                        		sscanf(&process_buf[i+1],"%d",&rcnt);
                		}
				if (rcnt<1){rcnt=1;}
				if (rcnt>4){rcnt=4;}
				i = strpos(process_buf,",",5);
                		if (i>=0){
                        		sscanf(&process_buf[i+1],"%d",&offset);
                		}
				if (offset<1){offset=1;}
				i = strpos(process_buf,",",6);
                		if (i>=0){
					run_gccode(idx,freq,rcnt,offset,&process_buf[i+1]);
				}
			}
		}
		

		sprintf(line_buf,"completeir,1:%d,%d\r",idx,idc);
		write(socket_fp,line_buf,strlen(line_buf));
	}else{
		sprintf(line_buf,"unknowncommand,ERR_01\r");
		write(socket_fp,line_buf,strlen(line_buf));
	}
	return 1;
}

int process_uartstr (char * process_buf, int process_len, int socket_fp, int queued){

 	// we will return 0 if not a BB command, else 1
	
	// command format
	// all BB commands are preceeded by Q

	// QSTATVER
	//   returns this version
	//    returns status of attached irusb devices

	// QUPDATEFW
	//    will update fw of all attached irusb devices
	
	//   network commands
	// Q
	//  SIRPULSE (id=#) (r=#) hex_code

	// process_len DOES NOT include the CR

	


	//FILE * fp;
	char line_buf[2048];
	char devid[64];
	int rv,i,idx;
	char *j;

	int param[8];
	//char line_buf2[2048];

	//char remote[24];
	//char ircode[24];

	// first check for our command
	if (process_buf[0]=='Q'){
		
		if (!strncmp(&process_buf[1],"STATVER",7)){
			echoack(process_buf, process_len, socket_fp);
			//sprintf(line_buf, "%s\r",vers_string);
			sprintf(line_buf, "%s\r",vers_string);
			write(socket_fp,line_buf,strlen(line_buf));
			write_status(socket_fp);
			return 1;
		}else if (!strncmp(&process_buf[1],"UPDATEFW",8)){
			echoack(process_buf, process_len, socket_fp);
			// run the firmware update
			#ifdef INC_FW
			run_updatefw(socket_fp);
			#endif
			return 1;
		}else if (!strncmp(&process_buf[1],"CAPNEXT",7)){
			echoack(process_buf, process_len, socket_fp);
			webcapture=4;   // send 4th capture to web client sock
			return 1;
		}else if (!strncmp(&process_buf[1],"RESTART",7)){
			echoack(process_buf, process_len, socket_fp);		
			restart_app=1;
			return 1;

		}else if (!strncmp(&process_buf[1],"NCCREATE",8)){
			rv = create_fbcreds();
                        echoack(process_buf, process_len, socket_fp);
                        sprintf(line_buf, "%d\r",rv);     // values in file
                        write(socket_fp,line_buf,strlen(line_buf));
                        return 1;
                }else if (!strncmp(&process_buf[1],"NCEMAIL",7)){
			rv = email_fbcreds();
                        echoack(process_buf, process_len, socket_fp);
                        sprintf(line_buf, "%d\r",rv);      // values in file
                        write(socket_fp,line_buf,strlen(line_buf));
                        return 1;
                }else if (!strncmp(&process_buf[1],"NCRESET",7)){
			rv = reset_fbcreds();
                        echoack(process_buf, process_len, socket_fp);
                        sprintf(line_buf, "%d\r",rv);      // values in file
                        write(socket_fp,line_buf,strlen(line_buf));
                        return 1;
                }else if (!strncmp(&process_buf[1],"NCCHECK",7)){
			rv = check_fbcreds();
                        echoack(process_buf, process_len, socket_fp);
                        sprintf(line_buf, "%d\r",rv);      // values in file
                        write(socket_fp,line_buf,strlen(line_buf));
                        return 1;
		}else if (!strncmp(&process_buf[1],"STATNC",6)){
                        echoack(process_buf, process_len, socket_fp);
                        //struct stat statb;
                        int fbin=0;
                        int fbrun=0;
                        //if (stat("/root/fb_f",&statb)==0){fbin=1;}
			fbin=1;
                        if (fb_pid>0){fbrun=1;}
                        sprintf(line_buf, "%d %d\r",fbin, fbrun);
                        write(socket_fp,line_buf,strlen(line_buf));
                        return 1;
		
		}else if (!strncmp(&process_buf[1],"SIRPULSE",8)){
			// pulse ir id=######## r=## hex_code      (id is 32b hex)
			write(socket_fp,"QSIRPULSE\rOK\r",13);
			if (process_len>20){
				if ((queued>0)&&(strncmp(lastircode,&process_buf[10],process_len-10)==0)){
					syslog(LOG_INFO,"Queued command ignored %d",queued);
				}else{
					// this command will be BLOCKING
					run_ircode(&process_buf[10], process_len-10, -1);
				}
				strncpy(lastircode,&process_buf[10],process_len-10);
				lastircode[process_len-10]=0;
			}
			return 1;
		}else if (!strncmp(&process_buf[1],"HIDCODE",7)){
			echoack(process_buf, process_len, socket_fp);		
			if (process_len>14){
			sendhid(getdec(&process_buf[8],1),getdec(&process_buf[9],3),getdec(&process_buf[12],3));
			}
			return 1;
		}else if (!strncmp(&process_buf[1],"SIRSTART",8)){
			// start ir hex_code
			write(socket_fp,"QSIRSTART\rNAK\r",14);
			// not implemented
			return 1;
		}else if (!strncmp(&process_buf[1],"SIRSTOP",7)){
			// stop ir
			write(socket_fp,"QSIRSTOP\rNAK\r",13);
			// not implemented
			return 1;
	#ifdef INC_FB
		}else if (!strncmp(&process_buf[1],"DIRCODE",7)){
                        echoack(process_buf, process_len, socket_fp);
                        ircode_cmd(process_buf,process_len,socket_fp,8,queued);
                        return 1;
		}else if (!strncmp(&process_buf[1],"SIRCODE",7)){
                        echoack(process_buf, process_len, socket_fp);
                        ircode_cmd(process_buf,process_len,socket_fp,8,queued);
                        return 1;
		}else if (!strncmp(&process_buf[1],"SIRNCODE",8)){
                        echoack(process_buf, process_len, socket_fp);
                        ircoden_cmd(process_buf,process_len,socket_fp,9,queued);
                        return 1;
	#endif

		}else if (!strncmp(&process_buf[1],"MOTCONFS",8)){
			write(socket_fp,"QMOTCONFS\rOK\r",13);
			// scan params
			for (i=0;i<8;i++){
				param[i]=0;
			}
			param[5]=6;
			strncpy(line_buf,&process_buf[10],process_len-10);
			line_buf[process_len-10]=0;
			devid[0]=0;
			j = line_buf;
			// check for ID
			if (strstr(line_buf,"ID=")){
				strncpy(devid,strstr(line_buf,"ID=")+3,8);
				devid[8]=0;
				j=strstr(line_buf,"ID=")+12;
			}else if(strstr(line_buf,"id=")){
                		strncpy(devid,strstr(line_buf,"id=")+3,8);
                		devid[8]=0;
				j=strstr(line_buf,"id=")+12;
			}
			sscanf(j, "%d %d %d %d %d %d",&param[0],&param[1],&param[2],&param[3],&param[4],&param[5]);

			// make cmd
			line_buf[0]='D';
			for (i=0;i<6;i++){
				line_buf[i+1]=(unsigned char)param[i];
			}
			line_buf[7]=0;
			write_cmd(0, line_buf, 7, devid);
			return 1;
		}else if (!strncmp(&process_buf[1],"MOTCONFH",8)){
			write(socket_fp,"QMOTCONFH\rOK\r",13);
			// scan params
			for (i=0;i<8;i++){
				param[i]=0;
			}
			strncpy(line_buf,&process_buf[11],process_len-11);
			line_buf[process_len-11]=0;
			devid[0]=0;
			j = line_buf;
			idx = process_buf[9] - 0x30;
			if ((idx>=0)&&(idx<8)){
			// check for ID
			if (strstr(line_buf,"ID=")){
				strncpy(devid,strstr(line_buf,"ID=")+3,8);
				devid[8]=0;
				j=strstr(line_buf,"ID=")+12;
			}else if(strstr(line_buf,"id=")){
                		strncpy(devid,strstr(line_buf,"id=")+3,8);
                		devid[8]=0;
				j=strstr(line_buf,"ID=")+12;
			}
			sscanf(j, "%01d%03d%03d",&param[0],&param[1],&param[2]);

			// make cmd
			line_buf[0]='U';
			line_buf[1]=(unsigned char)idx;
			for (i=0;i<3;i++){
				line_buf[i+2]=(unsigned char)param[i];
			}
			if (param[0]==9){
				line_buf[2]=0x83;
				line_buf[3]=0x04;
				line_buf[4]=0x0;
			}
			line_buf[5]=0;
			write_cmd(0, line_buf, 5, devid);
			}
			return 1;
		}else if (!strncmp(&process_buf[1],"MOTCONFI",8)){
			write(socket_fp,"QMOTCONFI\rOK\r",13);
			strncpy(line_buf,&process_buf[11],process_len-11);
			line_buf[process_len-11]=0;
			devid[0]=0;
			idx = process_buf[9] - 0x30;
			if ((idx>=0)&&(idx<2)){
				run_ircode(line_buf, strlen(line_buf),idx);
			}
			return 1;
		}else if (!strncmp(&process_buf[1],"MOTCONFR",8)){
			write(socket_fp,"QMOTCONFR\rOK\r",13);
			devid[0]=0;
			if (process_len>10){
			strncpy(line_buf,&process_buf[10],process_len-10);
			line_buf[process_len-10]=0;
			// check for ID
			if (strstr(line_buf,"ID=")){
				strncpy(devid,strstr(line_buf,"ID=")+3,8);
				devid[8]=0;
			}else if(strstr(line_buf,"id=")){
                		strncpy(devid,strstr(line_buf,"id=")+3,8);
                		devid[8]=0;
			}
			}

			// make cmd
			line_buf[0]='C';
			line_buf[1]=0;
			write_cmd(socket_fp, line_buf, 1, devid);
			return 1;
		}else if (!strncmp(&process_buf[1],"MOTCONFZ",8)){
			write(socket_fp,"QMOTCONFZ\rOK\r",13);
			strncpy(line_buf,&process_buf[10],process_len-10);
			line_buf[process_len-10]=0;
			devid[0]=0;
			// check for ID
			if (strstr(line_buf,"ID=")){
				strncpy(devid,strstr(line_buf,"ID=")+3,8);
				devid[8]=0;
			}else if(strstr(line_buf,"id=")){
                		strncpy(devid,strstr(line_buf,"id=")+3,8);
                		devid[8]=0;
			}

			// make cmd
			line_buf[0]='Z';
			line_buf[1]=0;
			write_cmd(0, line_buf, 1, devid);
			return 1;
		}else{return 0;}
	}else{
		return 0;

	}
	return 0;
} 
