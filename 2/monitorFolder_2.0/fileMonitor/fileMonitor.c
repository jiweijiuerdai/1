#include <sys/inotify.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <errno.h>

//#define _DEBUG
#define _DAEMON

#define EVENT_NUM 16
#define BUF_SIZE 10240
#ifdef _DAEMON
char * fileConf = "/etc/fileMonitor.conf";
char * fileScan = "/etc/fileMonitor.scan";
char * fileLog = "/etc/fileMonitor.log";
#else
char * fileConf = "fileMonitor.conf";
char * fileScan = "fileMonitor.scan";
char * fileLog = "fileMonitor.log";
#endif
struct wd_name
{
	int wd;
	char * name;
};
int wd_NUM = 0;
struct wd_name * wd_array;

//struct stat buf;	// for detimine the type of file.

const int filenameLen = 500;
const int filelistLen = 10000;
char files[10000][500];
char buffer[BUF_SIZE];
char logmsg[500];
FILE * fplog;

int fd, wd;
char *offset = NULL;
struct inotify_event *event;
int len, tmp_len;
char strbuf[16];
int i = 0;

int m_argc;
char **m_argv;	

int sleeptime=1;

char * event_array[]=
{
	"File was accessed",
	"File was modified",
	"File attributes were changed",
	"writtable file closed",
	"Unwrittable file closed",
	"File was opened",
	"File was moved from X",
	"File was moved to Y",
	"Subfile was created",
	"Subfile was deleted",
	"Self was deleted",
	"Self was moved",
	"",
	"Backing fs was unmounted",
	"Event queued overflowed",
	"File was ignored"
};

int init(int argc, char **argv);

int readConfig(char * filename);
int resetConfig(char * filename);
int readScan(char * filename, int cur);
int parseCmd(char * filename,int argc,  char **argv);
int execCmd(char** dirs, char** f_files, char** filetypes, int dsize,int fsize, int tsize, char * filename, int flag);
// no recursively
int execCmdN(char** dirs,int dsize, char * filename,int cur);
// recursively
int execCmdR(char** dirs, int dsize, char * filename,int cur);
// with file type
int execCmdT(char** dirs, char** filetypes, int dsize, int tsize, char * filename,int cur);
// only files
int execCmdF(char** f_files,int fsize,int cur);

char * getTime()
{
	time_t now; 
    struct tm  *timenow; 
    char strtemp[500]; 
       
    time(&now); 
    timenow = (struct tm *)localtime(&now); 
	return (char*)asctime(timenow);
 	//printf("recent time is : %s \n", asctime(timenow)); 
}

//for select
int  isready(int  fd)
{
    int    rc;
    fd_set    fds;
    struct timeval    tv;
    FD_ZERO(&fds);
    FD_SET(fd,  &fds);
    tv.tv_sec = tv.tv_usec = 0;
    rc = select(fd+1, &fds, NULL, NULL, &tv);
    if( rc<0 )  //error
      exit(-1);
	return FD_ISSET(fd, &fds)  ? 1: 0;
}


//for daemon
#define LOCKFILE "/var/run/fileMonitor.pid"  
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) 

int daemonize(const char *cmd)
{
    int i,fd0,fd1,fd2;
    pid_t pid;
    struct rlimit r1;
    struct sigaction sa;

    umask(0); //Clear file creation mask

    if(getrlimit(RLIMIT_NOFILE,&r1) < 0)
    {
        printf("getrlimit error.\n");
        exit(1);
    }

    if((pid = fork()) < 0 )
    {
        printf("fork1 error.\n");
        exit(2);
    }
    else if(pid > 0)//Parent
    {
        exit(0);
    }

    setsid();

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
	if(sigaction(SIGHUP,&sa,NULL)<0) 
    {
        printf("sigaction error.\n");
        exit(3);                 
    }                            

    if((pid=fork()) < 0)         
    {                 
	    printf("fork2 error.\n");
        exit(2);
    }                                                                                                                                    
    else if(pid > 0)         
    {
        exit(0);             
    }                                                                                                                                    
  
    if(chdir("/") < 0)       
    {                
    	printf("chdir error.\n");
        exit(4);
    }                                                                                                                                    
    
   //close(0); /* close stdin */ 	// for file.scan and file.conf
	//close(1); /* close stdout */ //  for file.scan and file.conf
	//close(2); /* close stderr */
  
    openlog(cmd,LOG_PID, LOG_USER);  
  
    syslog(LOG_INFO,"fileMonitor Start\n");
}


int lockfile(int fd)
{                                                                                                                                        
    struct flock f1;

    f1.l_type = F_WRLCK;
    f1.l_start = 0;
    f1.l_whence = SEEK_SET;
    f1.l_len = 0;
  
    return(fcntl(fd,F_SETLK,&f1));
}                                                                                                                                        
  
int already_running(void)
{                                                                                                                                        
    int fd;
    char buf[16];
  
    fd = open(LOCKFILE,O_RDWR|O_CREAT,LOCKMODE);
    if(fd < 0)
    {   
    	printf("Can't Open %s:%s\n",LOCKFILE,strerror(errno));
        syslog(LOG_INFO,"Can't Open %s:%s",LOCKFILE,strerror(errno)); 
        exit(1);
    }                                                                                                                                    
    if(lockfile(fd) < 0)
    {
        if(errno == EACCES || errno == EAGAIN)
        {
            close(fd);
            return 1;
        }                                                   
        printf("Can't lock %s:%s\n",LOCKFILE,strerror(errno));
        syslog(LOG_INFO,"Can't lock %s:%s",LOCKFILE,strerror(errno));
        exit(1);
    }                                                                                                                                    
  
    ftruncate(fd,0);
    sprintf(buf,"%ld",(long)getpid());
    write(fd,buf,strlen(buf));
    return 0;
}                                                                                                                                        
 
void sigterm(int signo)
{                                                                                                                                        
    syslog(LOG_INFO,"got SIGTERM,EXIT");
    fclose(fplog);
    closelog();
    exit(0);
}                                                                                                                                        
 
void reread(void)
{                                                                                                                                        
    syslog(LOG_INFO,"Re-read configuration file ok");
    init(m_argc, m_argv);
} 

void sighup(int signo)
{                                                                                                                                        
    syslog(LOG_INFO,"Re-Reading configuration file");
    reread();
}  
int main(int argc, char **argv)
{
#ifdef _DAEMON
	struct sigaction sa;
    daemonize(argv[0]);          
    if(already_running())
    {
		printf("fileMonitor already running\n");
        syslog(LOG_INFO,"fileMonitor already running\n");
        exit(2);
    }           
  
    sa.sa_handler = sigterm;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask,SIGTERM);  
    sa.sa_flags = 0;   
    if(sigaction(SIGTERM,&sa,NULL) < 0)
    {                                  
        syslog(LOG_INFO,"Can't Catch SIGTERM:%s",strerror(errno));
        exit(1);
    }           
  
    sa.sa_handler = sighup;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask,SIGHUP);
    sa.sa_flags = 0; 
    if(sigaction(SIGHUP,&sa,NULL) < 0)
    {                                 
        syslog(LOG_INFO,"Can't catch SIGHUP:%s",strerror(errno));
        exit(1);
    } 
#endif

	m_argc = argc;
	m_argv = argv;
	fd = inotify_init();
	if (fd < 0) {
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Fail to initialize inotify.\n");
			syslog(LOG_INFO,logmsg);
#else				
		printf("Fail to initialize inotify.\n");
#endif		
		exit(-1);
	}
	fplog = fopen(fileLog,"wb");

	init(m_argc, m_argv);
	memset(logmsg,0,500);

	while(1)
	{
		if (isready(fd)) 
		{	 
			if(len = read(fd, buffer, BUF_SIZE)) {
				offset = buffer;
#ifdef _DAEMON
					memset(logmsg,0,500);
					sprintf(logmsg,"%s\tSome event happens, len = %d.\n",getTime(), len);
					syslog(LOG_INFO,logmsg);
#else				
				memset(logmsg,0,500);
				sprintf(logmsg,"%s\tSome event happens, len = %d.\n",getTime(), len);
				fwrite(logmsg, 1 , sizeof(logmsg),fplog);
#endif

#ifdef _DEBUG		
				printf("%s\tSome event happens, len = %d.\n",getTime(), len);
#endif

				event = (struct inotify_event *)buffer;
				while (((char *)event - buffer) < len)
				{
					if (event->mask & IN_ISDIR)
					{
						strcpy(strbuf, "Direcotory");
					}
					else
					{
						strcpy(strbuf, "File");
					}
#ifdef _DEBUG
#ifdef _DAEMON
					memset(logmsg,0,500);
					sprintf(logmsg,"\tObject type: %s\n", strbuf);
					syslog(LOG_INFO,logmsg);
#else						
					memset(logmsg,0,500);
					sprintf(logmsg,"\tObject type: %s\n", strbuf);
					fwrite(logmsg, 1 , sizeof(logmsg),fplog);
					printf("\tObject type: %s\n", strbuf);
#endif
#endif			
					for (i=0; i<wd_NUM; i++)
					{
						if (event->wd != wd_array[i].wd) continue;
#ifdef _DAEMON
					memset(logmsg,0,500);
					sprintf(logmsg,"\tObject name: %s\n", wd_array[i].name);
					syslog(LOG_INFO,logmsg);
#else
						memset(logmsg,0,500);
						sprintf(logmsg,"\tObject name: %s\n", wd_array[i].name);
						fwrite(logmsg, 1 , sizeof(logmsg),fplog);
#ifdef _DEBUG
						printf("\tObject name: %s\n", wd_array[i].name);
#endif
#endif
						break;
					}
#ifdef _DEBUG
#ifdef _DAEMON
					memset(logmsg,0,500);
					sprintf(logmsg,"\tEvent mask: %08X\n", event->mask);
					syslog(LOG_INFO,logmsg);
#else							
					memset(logmsg,0,500);
					sprintf(logmsg,"\tEvent mask: %08X\n", event->mask);
					fwrite(logmsg, 1 , sizeof(logmsg),fplog);
					printf("\tEvent mask: %08X\n", event->mask);
#endif
#endif
					for (i=0; i<EVENT_NUM; i++)
					{
						if (event_array[i][0] == '\0') continue;
						if (event->mask & (1<<i))
						{
#ifdef _DAEMON
					memset(logmsg,0,500);
					sprintf(logmsg,"\tEvent: %s\n", event_array[i]);
					syslog(LOG_INFO,logmsg);
#else						
							memset(logmsg,0,500);
							sprintf(logmsg,"\tEvent: %s\n", event_array[i]);
							fwrite(logmsg, 1 , sizeof(logmsg),fplog);
#ifdef _DEBUG
							printf("\tEvent: %s\n", event_array[i]);
#endif
#endif
						}
					}
					tmp_len = sizeof(struct inotify_event) + event->len;
					event = (struct inotify_event *)(offset + tmp_len); 
					offset += tmp_len;
				}
				fflush(fplog);
			}

		}
#ifdef _DAEMON
					memset(logmsg,0,500);
					sprintf(logmsg,"\tEsleep time %d\r",sleeptime);
					syslog(LOG_INFO,logmsg);
#else		
		printf("sleep time %d\r", sleeptime);
		fflush(stdout);
#endif
		fflush(stdout);
		init(m_argc, m_argv);
		read(fd, buffer, BUF_SIZE);
		sleep(sleeptime);
	}
	
	return 0;
}

// read the configure from file.conf
int readConfig(char * filename)
{
	FILE * fp;
	fp = fopen(filename,"r");
	if(fp == NULL)
	{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%s created.\n", filename);
			syslog(LOG_INFO,logmsg);
#else						
		printf("No %s exists.\n", filename);
		printf("%s created.\n", filename);
#endif
		resetConfig(filename);
		fp = fopen(filename,"r");
		if(fp == NULL)
		{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%s can not read.\n", filename);
			syslog(LOG_INFO,logmsg);
#else						
		printf("%s can not read.\n", filename);
#endif		
			exit(-1);
		}	
			
	}
	
	int cur_file = 0;
	int cur_dir = 0;
	int cur_type = 0;
	char *f_dirs[500];	// for record the files 
						//so the max dirs cmd list len is 500
	char *fileTypes[500];	// for record the file type 
						// so the max fileType cmd list len is 500
	char *f_files[500];	// for record the files 
						// so the max fileType cmd list len is 500
	char * p;
	int i;
	int rflag = 0;
	int type = 0;

	int ret = 0;
	while(!feof(fp) && type < 4)
	{
		fgets(buffer,filenameLen, fp);
		if(buffer[0] == '#')
		{
#ifdef _DEBUG 
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d %s",strlen(buffer),buffer);
			syslog(LOG_INFO,logmsg);
#else						
			printf("%d %s",strlen(buffer),buffer);
			fflush(stdout);
#endif
#endif			
			continue;
		}
		if(0 == strcmp(buffer, "[DIRECTORY]\n"))
		{
			type++;
			fgets(buffer,filenameLen, fp);

			if(strlen(buffer) > 1)
				while(!feof(fp) && buffer[0] != '#' && 0!= strcmp(buffer,"[FILE]\n"))
				{
#ifdef _DEBUG 
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d %s",strlen(buffer),buffer);
			syslog(LOG_INFO,logmsg);
#else				
					printf("%d %s",strlen(buffer),buffer);
					fflush(stdout);
#endif
#endif	
					if(strlen(buffer) > 1)
					{
						int len = strlen(buffer);
						buffer[len-1]='\0';
						f_dirs[cur_dir] = (char *) malloc(sizeof(char)*500);
						strcpy(f_dirs[cur_dir], buffer); // save type
						cur_dir++;
					}
					fgets(buffer,filenameLen, fp);
				}
		}
		else if(0 == strcmp(buffer, "[FILE]\n"))
		{
			type++;
			fgets(buffer,filenameLen, fp);

			if(strlen(buffer) > 1)
				while(!feof(fp) && buffer[0] != '#' && 0!= strcmp(buffer,"[FILE_TYPE]\n"))
				{
#ifdef _DEBUG 
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d %s",strlen(buffer),buffer);
			syslog(LOG_INFO,logmsg);
#else				
					printf("%d %s",strlen(buffer),buffer);
					fflush(stdout);
#endif
#endif	
					if(strlen(buffer) > 1)
					{
						int len = strlen(buffer);
						buffer[len-1]='\0';
						f_files[cur_file] = (char *) malloc(sizeof(char)*500);
						strcpy(f_files[cur_file], buffer); // save type
						cur_file++;
					}
					fgets(buffer,filenameLen, fp);
				}
		}
		else if(0 == strcmp(buffer, "[FILE_TYPE]\n"))
		{
			type++;
			fgets(buffer,filenameLen, fp);

			if(strlen(buffer) > 1)
				while(!feof(fp) && buffer[0] != '#' && 0!= strcmp(buffer,"[Time]\n"))
				{
#ifdef _DEBUG 
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d %s",strlen(buffer),buffer);
			syslog(LOG_INFO,logmsg);
#else						
					printf("%d %s",strlen(buffer),buffer);
					fflush(stdout);
#endif
#endif	
					if(strlen(buffer) > 1)
					{
						int len = strlen(buffer);
						buffer[len-1]='\0';
						fileTypes[cur_type] = (char*)malloc(sizeof(char) * 500);
						strcpy(fileTypes[cur_type],buffer);	// save it
						cur_type++;
					}
					fgets(buffer,filenameLen, fp);
				}
		}
		else if(0 == strcmp(buffer, "[Time]\n"))
		{
			type++;
			fgets(buffer,filenameLen, fp);

			if(strlen(buffer) > 1)
				while(!feof(fp) && buffer[0] != '#')
				{
#ifdef _DEBUG 
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d %s",strlen(buffer),buffer);
			syslog(LOG_INFO,logmsg);
#else						
					printf("%d %s",strlen(buffer),buffer);
					fflush(stdout);
#endif
#endif	
					if(strlen(buffer) > 1)
					{
						int len = strlen(buffer);
						//buffer[len-1]='\0';
						
						sleeptime = atoi(buffer);
						
					}
					fgets(buffer,filenameLen, fp);
				}
		}
		
	}
	if(type != 4)
	{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%s is broken. Reset the configure....\n", filename);
			syslog(LOG_INFO,logmsg);
			resetConfig(filename);
			memset(logmsg,0,500);
			sprintf(logmsg,"%s is read again....\n", filename);
			syslog(LOG_INFO,logmsg);
			return readConfig(filename);
#else						
		printf("%s is broken. Reset the configure....\n", filename);
		resetConfig(filename);
		printf("%s is read again....\n", filename);
		return readConfig(filename);
#endif

	}
	if(cur_dir + cur_file == 0 || (cur_dir ==0 && cur_type != 0))
	{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%s is not configured correctly. Set the configure please.\n", filename);
			syslog(LOG_INFO,logmsg);
#else						
		printf("%s is not configured correctly. Set the configure please.\n", filename);
#endif
		//resetConfig(filename);
		exit(-1);
	}

#ifdef _DEBUG	
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d lines read %d types.\n",cur_dir +cur_type + cur_file, cur_type);
			syslog(LOG_INFO,logmsg);
#else				
	printf("%d lines read %d types.\n",cur_dir +cur_type + cur_file, cur_type);
#endif
#endif		
	fclose(fp);
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is readConfig function. \n");
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is readConfig function. \n");
	fflush(stdout);
#endif
#endif
		// default is with recursively
	ret = execCmd(f_dirs, f_files, fileTypes, cur_dir, cur_file, cur_type, fileScan, 1);

#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is readConfig function. ret %d\n",ret);
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is readConfig function. ret %d\n",ret);
	fflush(stdout);
#endif
#endif
	for(i = 0; i < cur_dir; i++)
	{
		free(f_dirs[i]);
			
	}
	for(i = 0; i < cur_type; i++)
	{
		free(fileTypes[i]);		
	}

	return ret;
}

// reset the file.conf if error
int resetConfig(char * filename)
{
	FILE * fp;
	fp = fopen(filename,"w");
	if(fp == NULL)
	{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Can not open %s\n", filename);
			syslog(LOG_INFO,logmsg);
#else						
		printf("Can not open %s\n", filename);
#endif
		exit(-1);
	}
	fputs("#This is the configure file for fileMonitor.\n", fp);
	fputs("#DO NOT CHANGE the structure of this file.\n", fp);
	fputs("#In this place you can add the directories to be monitored.\n", fp);
	fputs("#Be aware that there is no space in front of each line.\n", fp);
	fputs("#Remmember that PRESS Enter at the end of each line.\n", fp);
	fputs("#EXAMPLE|/home/tuxe/dir\n", fp);
	fputs("[DIRECTORY]\n", fp);
	fputs("/home\n\n", fp);
	
	fputs("#In this place you can add the files to be monitored.\n", fp);
	fputs("#Be aware that there is no space in front of each line.\n", fp);
	fputs("#Remmember that PRESS Enter at the end of each line.\n", fp);
	fputs("#EXAMPLE|/home/tuxe/file\n", fp);
	fputs("[FILE]\n\n", fp);
	
	fputs("#In this place you can add file types to be monitored.\n", fp);
	fputs("#Be aware that there is no space in front of each line.\n", fp);
	fputs("#Remmember that PRESS Enter at the end of each line.\n", fp);
	fputs("#EXAMPLE|*.txt\n", fp);
	fputs("[FILE_TYPE]\n", fp);
	fputs("*.txt\n\n", fp);
	
	fputs("#In this place you can add time option.\n", fp);
	fputs("#Be aware that there is no space in front of each line.\n", fp);
	fputs("#Remmember that PRESS Enter at the end of each line.\n", fp);
	fputs("#EXAMPLE|2\n", fp);
	fputs("[Time]\n", fp);
	fputs("1\n\n", fp);
	
	fclose(fp);
}

// parse the cmd and set files 
// return the wd_NUM;
int parseCmd(char * filename, int argc, char **argv)
{
	int cmd_num = argc - 1;
	int offset = 1;
	// this test is no necessary.
	if(cmd_num <= 0)
	{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Unknown error.\n");
			syslog(LOG_INFO,logmsg);
#else						
		printf("Unknown error.\n");
#endif
		exit(-1);
	}
	
	int cur_file = 0;
	int cur_dir = 0;
	int cur_type = 0;
	char *f_dirs[500];	// for record the files 
						//so the max dirs cmd list len is 500
	char *fileTypes[500];	// for record the file type 
						// so the max fileType cmd list len is 500
	char *f_files[500];	// for record the files 
						// so the max fileType cmd list len is 500
	char * p;
	int i;
	char type = 'a';
	int rflag = 0;
	for(i = 0; i < cmd_num; i++)
	{
		p = argv[i + offset];
		if(0 == strcmp(p, "--help"))
		{
			printf("Usage:fileMonitor -d dirs -f files [-t fileTypes]\n\
 --help	show help information\n\
 -f		this is to set some files\n		example -f /home/file1 /home/n.c\n\
 -d		this is to set some directories\n		example -d /home /tmp\n\
 -t		this is optional to set some file_types\n		example -t *.txt *.png\n\
 -n		set the time to monitor the directories\n		example -n 2\n\
 -r		to monitor with recursively\n\
 This program is used for monitor some files coded by Ren Gaojun, China.\n");
			fflush(stdout);

			exit(0);
		}
		if(0 == strcmp(p, "-f"))
		{
			type = 'f';
			continue;
		}
		else if(0 == strcmp(p, "-d"))
		{
			type = 'd';
			continue;
		}
		else if(0 == strcmp(p, "-t"))
		{
			type = 't';
			continue;
		}
		else if(0 == strcmp(p,"-r"))
		{
			type = 'a';
			rflag = 1;
			continue;
		}
		else if(0 == strcmp(p,"-n"))
		{
			type = 'n';
			continue;
		}
		
	    if( type == 'f')
		{
			f_files[cur_file++] = p;
#ifdef _DEBUG	
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"type f %s \n",p);
			syslog(LOG_INFO,logmsg);
#else				
			printf("type f %s \n",p);
#endif
#endif
		}
		else if( type == 'd')
		{
			f_dirs[cur_dir++] = p;
#ifdef _DEBUG	
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"type d %s \n",p);
			syslog(LOG_INFO,logmsg);
#else						
			printf("type d %s \n",p);
			
#endif			
#endif
		}
		else if( type == 't')
		{
			fileTypes[cur_type++] = p;
#ifdef _DEBUG	
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"type t %s \n",p);
			syslog(LOG_INFO,logmsg);
#else						
			printf("type t %s \n",p);
#endif
#endif
		}
		else if( type == 'n')
		{
			sleeptime = atoi(p);
#ifdef _DEBUG	
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"type n %s \n",p);
			syslog(LOG_INFO,logmsg);
#else						
			printf("type n %s \n",p);
#endif
#endif
		}
	}
#ifdef _DEBUG	
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d cmd_num %d dirs %d files %d types %d rflag.\n",cmd_num,cur_dir, cur_file, cur_type, rflag);
			syslog(LOG_INFO,logmsg);
#else				
	printf("%d cmd_num %d dirs %d files %d types %d rflag.\n",cmd_num,cur_dir, cur_file, cur_type, rflag);
#endif
#endif		
	return execCmd(f_dirs,f_files, fileTypes, cur_dir,cur_file, cur_type, filename, rflag);
	
}

// execute the command to get the file list with recursively.
int execCmd(char** dirs, char** f_files, char** filetypes, int dsize,int fsize, int tsize, char * filename, int flag)
{
	int i = 0;
	int ret = 0;
	memset(buffer,0,BUF_SIZE);
	//sprintf(buffer,"find %s -name '%s' > file.scan",argv[1] , argv[2]);
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmd function.\n");
			syslog(LOG_INFO,logmsg);
#else				
	printf("Here is execCmd function.\n");
	fflush(stdout);
#endif
#endif
	if(tsize > 0) // with filetype
	{
		ret = execCmdT(dirs,filetypes,dsize, tsize, filename,0);
	}
	if(fsize > 0)
		ret = execCmdF(f_files,fsize, ret);
	if(dsize > 0)
	{
		if(!flag)		// not set the recursively flag
			ret = execCmdN(dirs,dsize, filename,ret);
		else
			ret = execCmdR(dirs,dsize, filename,ret);
	}
	
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmd function. ret %d\n", ret);
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmd function. ret %d\n", ret);
	fflush(stdout);
#endif
#endif
	return ret;

}
// with file type.
int execCmdT(char** dirs, char** filetypes, int dsize, int tsize, char * filename,int cur)
{
	int i =0;
	int ret = cur;
	memset(buffer,0,BUF_SIZE);

#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdT function. dsize %d, tsize %d\n", dsize, tsize);
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmdT function. dsize %d, tsize %d\n", dsize, tsize);
	fflush(stdout);
#endif
#endif

	strcpy(buffer,"find ");

	for(i = 0; i < dsize; i++)
	{
		strcat(buffer,dirs[i]);
		strcat(buffer," ");
	}

	strcat(buffer,"-name '");

	char tmp[BUF_SIZE];
	strcpy(tmp,buffer);	// save the buffer.
	for(i = 0; i < tsize; i++)	// each time search one type of file 
	{
		strcat(buffer,filetypes[i]);
		strcat(buffer,"' > ");
		strcat(buffer,filename);
		system(buffer);
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%s\n",buffer);
			syslog(LOG_INFO,logmsg);
#else						
		printf("%s\n",buffer);
		fflush(stdout);
#endif
#endif
		ret = readScan(filename,ret);
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"ret %d %s\n",ret, filename);
			syslog(LOG_INFO,logmsg);
#else						
		printf("ret %d %s\n",ret, filename);
		fflush(stdout);
#endif
#endif
		strcpy(buffer,tmp);
	}

#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdT function. ret %d\n", ret);
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmdT function. ret %d\n", ret);
	fflush(stdout);
#endif
#endif
	return ret;
}

// execute the command to get the file list with recursively.
int execCmdR(char** dirs, int dsize, char * filename,int cur)
{
	int i = 0;
	int ret = cur;
	memset(buffer,0,BUF_SIZE);
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdR function. \n");
			syslog(LOG_INFO,logmsg);
#else				
	printf("Here is execCmdR function. \n");
	fflush(stdout);
#endif
#endif
	strcpy(buffer,"find ");
	for(i = 0; i < dsize; i++)
	{
		strcat(buffer,dirs[i]);
		strcat(buffer," ");
	}
//	strcat(buffer,"-type d > ");
	strcat(buffer," > ");
	strcat(buffer,filename);
	system(buffer);
	
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%s\n",buffer);
			syslog(LOG_INFO,logmsg);
#else					
	printf("%s\n",buffer);
	fflush(stdout);
#endif
#endif
	ret = readScan(filename,ret);	
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdR function. ret %d\n", ret);
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmdR function. ret %d\n", ret);
	fflush(stdout);
#endif
#endif
	return ret;
	
}
// execute the files
int execCmdF(char** f_files,int fsize,int cur)
{
	int i = 0;
	int ret = 0;
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdF function.\n");
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmdF function.\n");
	fflush(stdout);
#endif
#endif
	for(i = 0; i < fsize; i++)
	{
		strcpy(files[cur + i], f_files[i]);
	}
	ret = fsize + cur;	
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdF function. ret %d\n", ret);
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmdF function. ret %d\n", ret);
	fflush(stdout);
#endif
#endif
	return ret;
}
// execute the command to get the file list with no recursively.
// just monitor the directory no filetype 
int execCmdN(char** dirs,int dsize, char * filename,int cur)
{
	int i = 0;
	int ret = cur;
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdN function.\n");
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmdN function.\n");
	fflush(stdout);
#endif
#endif
	for(i = cur; i < dsize + cur; i++)
	{
		strcpy(files[i], dirs[i-cur]);
	}
	
	ret = i;	
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Here is execCmdN function. ret %d\n", ret);
			syslog(LOG_INFO,logmsg);
#else					
	printf("Here is execCmdN function. ret %d\n", ret);
	fflush(stdout);
#endif
#endif
	return ret;
}
int readScan(char * filename, int cur)
{
	int num = cur;
	FILE * fp;
	fp = fopen(filename,"r");
	if(fp == NULL)
	{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Fail to open %s.\n", filename);
			syslog(LOG_INFO,logmsg);
#endif				

		printf("Fail to open %s.\n", filename);

		exit(-1);
	}

	while(num < filelistLen && !feof(fp))		// read files and save them.
	{
		int L;
		fgets(files[num],filenameLen,fp);
		L = strlen(files[num]);
		if(L <= 1)
			break;
		files[num][L-1]='\0';
	
		num++;
	}
	return num;
}
int init(int argc, char **argv)
{
	for(i = 0; i< 1000; i++)
		memset(files[i],0,500);
	
	for(i = 0; i< wd_NUM; i++)
	{
		inotify_rm_watch(fd,wd_array[i].wd);
	}
	if(wd_NUM > 0)
		free(wd_array);

	if(argc == 1)
	{
		//puts("Monitor the files set in the file.conf");

		wd_NUM = readConfig(fileConf);
		if(wd_NUM <= 0)
		{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%s is empty.\n", fileConf);
			syslog(LOG_INFO,logmsg);
#else		
			printf("%s is empty.\n", fileConf);
#endif
			exit(-1);
		}
	}
	else
	{
		// read file from cmd.
		wd_NUM = parseCmd(fileScan,argc, argv);
		if(wd_NUM < 0)
		{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Command error.\n");
			syslog(LOG_INFO,logmsg);
#else					
			printf("Command error.\n");
#endif
			exit(-1);
		}
	}
	
	

	wd_array = (struct wd_name*)malloc(sizeof(struct wd_name) * wd_NUM);
	if(wd_array == NULL)
	{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Malloc error.\n");
			syslog(LOG_INFO,logmsg);
#else						
		printf("Malloc error.\n");
#endif		
		exit(-1);
	}
	
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"wd num :%d\n",wd_NUM);
			syslog(LOG_INFO,logmsg);
#else					
	printf("wd num :%d\n",wd_NUM);
#endif
#endif	
	for(i = 0; i< wd_NUM; i++)
	{
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"%d %s\n",i,files[i]);
			syslog(LOG_INFO,logmsg);
#else						
		printf("i=%d %s\n",i,files[i]);
#endif
#endif		
		wd_array[i].name = files[i];
		wd = inotify_add_watch(fd,wd_array[i].name, IN_ALL_EVENTS);
		if(wd < 0)
		{
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"Can't add watch for %s.\n", wd_array[i].name);
			syslog(LOG_INFO,logmsg);
#else						
			printf("Can't add watch for %s.\n", wd_array[i].name);
#endif			
			exit(-1);
			
		}
		else
			wd_array[i].wd = wd;
	}
#ifdef _DEBUG
#ifdef _DAEMON
			memset(logmsg,0,500);
			sprintf(logmsg,"init finished\n");
			syslog(LOG_INFO,logmsg);
#else						
		printf("init finished\n");
#endif
#endif	
	fflush(stdout);
	
	return 0;

}
