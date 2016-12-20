#!/bin/sh
#chkconfig: 2345 80 90
#description:fileMonitor
#/etc/init.d/fileMonitor
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin
binpath=/usr/local/bin/fileMonitor

test -f $binpath || exit 0

. /lib/lsb/init-functions

case "$1" in

start)

log_begin_msg "Starting fileMonitor..."

start-stop-daemon --start --quiet --exec $binpath

log_end_msg $?

;;

stop)

log_begin_msg "Stopping fileMonitor..."

start-stop-daemon --stop --retry TERM/1/TERM/1/TERM/4/KILL --quiet --oknodo --exec $binpath

log_end_msg $?

;;

restart|force-reload)

$0 stop

sleep 1

$0 start

;;

*)

log_success_msg "Usage: $binpath {start|stop|restart|force-reload}"

exit 1

esac

exit 0

#　　大致是这样，脚本可以按需要写的再细致些,做到这里按说已经完成，但是unix有个run level这个特征，所以我们必须对于特定的run level创建一个链接，
#　　一般linux是运行level 2，那么我们输入下列命令ln -s /etc/init.d/fileMonitor /etc/rc2.d/S50fileMonitor.
