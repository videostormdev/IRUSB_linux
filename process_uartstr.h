void set_samplemode(int socket_fp);
void set_defaultmode(int socket_fp);
void write_status(int socket_fp);
int process_uartstr(char *, int, int,int);
int process_gcstr(char *, int, int,int);
int read_fbcreds(char *fbun, char *fbpw);
void run_ircode(char *buf, int buf_len, int svcd);
int find_rxcode(char *devid, char *buf, char *rbuf);
char * getDevid(int i);
int* parse_hex(char *hexcode, float *per, int *intarr, int *arridx, int *sum);
void write_cmd(int socket_fp, char *cmd, int cmdlen, char *devid);
