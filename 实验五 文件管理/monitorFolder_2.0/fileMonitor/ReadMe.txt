[fileMonitor使用说明]

本程序名为fileMonitor，利用inotify机制进行文件或文件夹的监控。fileMonitor可以当成daemon程序进行(同一时刻只有一个实例)，产生的配置文件和临时文件将在/etc/目录下，也可以通过注释源文件的宏(#define _DAEMON)，然后重新编译，就可以变成普通程序，产生的来时文件和配置文件都将在当前目录下。

若为daemon程序时，本程序需要用root权限进行，不然将出错退出。当以root权限运行后，将会把日志记录在syslog中，用户可以通过查看/var/log/message文件了解程序运行的状况。若为普通程序时，将在当前目录产生日志文件fileMonitor.log，并记录程序运行的状况。此时若程序有定义(#define _DEBUG)宏，则会在屏幕上显示程序运行的状况，这是为了方便调试。

程序默认是设置了宏_DAEMON，并注释了_DEBUG。故只有在syslog中可以查看程序运行的状况。若有需要，可以修改宏，并重新编译安装。

文件包中有一个beService.sh脚本，这是把fileMonitor设置为服务程序，并设置开机启动的，此脚本需要以root权限运行。其本质是把fileMonitor.sh脚本复制到/etc/init.d/文件夹中，并重命名为fileMonitor，这样就可以通过使用sudo /etc/init.d/fileMonitor start|stop 来启动服务和停止服务，并通过设置chkconfig --add fileMonitor 或者通过建立/etc/init.d/fileMonitor 和 /etc/rc*.d/的相关连接来设置开机启动。

本程序是用来监控文件或者文件夹的应用程序，它可以接受命令行参数，也可以通过配置它的配置文件（/etc/fileMonitor.conf或者在工作目录下fileMonitor.conf）来指定文件或者文件夹。

关于命令行参数： fileMonitor [-d dirs] [-f files] [-r] [-t types] [--help]
[-d dirs] 	  设置扫描的文件夹
[-f files]	  设置扫描的文件
[-r] 		  如果这个选项设置，则递归的监控文件夹下所有的子文件夹
[-t types] 	  设置扫描的文件类型
[--help]	  显示帮助信息

关于配置文件（默认生成的如下所示）：
#This is the configure file for fileMonitor.
#DO NOT CHANGE the structure of this file.
#In this place you can add the directories to be monitored.
#Be aware that there is no space in front of each line.
#EXAMPLE|/home/tuxe/dir
[DIRECTORY]
/home

#In this place you can add the files to be monitored.
#Be aware that there is no space in front of each line.
#EXAMPLE|/home/tuxe/file
[FILE]

#In this place you can add file types to be monitored.
#Be aware that there is no space in front of each line.
#EXAMPLE|*.txt
[FILE_TYPE]
*.txt

用户可以在相关位置增加需要指定的文件夹，文件，和文件类型。


[fileMonitor源码包说明]

本程序为1.0版本，故源代码只有一个文件(fileMonitor.c)，通过autoconfig程序进行了配置。

在源码包内，包含了所需的COPYING AUTHORS NEWS等文件，里面已经填入详细信息。比如README文件，其内容如下：

README  //程序运行实例

This is fileMonitor program readme file.
fileMonitor is for monitor the files or directories to see if any changes happen, for example delete or create.

You can use it by set the configure file in /etc/fileMonitor.conf or you can use the command options.
Example: fileMonitor -d /home

Also, you can use it as a service. So that you can start fileMonitor like
sudo /etc/init.d/fileMonitor start

Remember you should start fileMonitor by root, or it will fail.


CONTACT

If you have problems, questions, ideas or suggestions, please contact me
by email to 2008rengaojun@sina.com.

WEB SITE

Visit the fileMonitor web site for the latest news and downloads:

http://gaojunren.com/fileMonitor

INSTALLATION  //程序安装命令

./configure

make

sudo make install

sudo ./beService.sh



[fileMonitor代码说明]

本程序拥有命令解析函数
int parseCmd(char * filename,int argc,  char **argv);

命令执行函数，这是一个函数家族，每一个功能不一样
int execCmd(char** dirs, char** f_files, char** filetypes, int dsize,int fsize, int tsize, char * filename, int flag);
// no recursively
int execCmdN(char** dirs,int dsize, char * filename,int cur);
// recursively
int execCmdR(char** dirs, int dsize, char * filename,int cur);
// with file type
int execCmdT(char** dirs, char** filetypes, int dsize, int tsize, char * filename,int cur);
// only files
int execCmdF(char** f_files,int fsize,int cur);

有读取配置文件的函数
int readConfig(char * filename);

创建或者重置配置文件函数
int resetConfig(char * filename);

读取解析命令时产生的临时文件的函数
int readScan(char * filename, int cur);

通过以下函数判断是否已经有实例运行，以保证只有一个实例运行在当前时间
int already_running(void);

通过以下函数把当前程序变成daemon程序
int daemonize(const char *cmd);

通过初始化，获得inotify实例
	fd = inotify_init();

通过inotify机制增加监控的文件或者文件夹
wd = inotify_add_watch(fd,wd_array[i].name, IN_ALL_EVENTS);

通过read函数获取当前发生的事件
len = read(fd, buffer, BUF_SIZE)

通过syslog记录程序的日志
syslog(LOG_INFO,logmsg);
