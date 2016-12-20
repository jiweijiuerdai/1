cp fileMonitor.sh /etc/init.d/fileMonitor
chmod a+rx /etc/init.d/fileMonitor

ln -sf /etc/init.d/fileMonitor /etc/rc0.d/K28fileMonitor
ln -sf /etc/init.d/fileMonitor /etc/rc1.d/K28fileMonitor
ln -sf /etc/init.d/fileMonitor /etc/rc2.d/K28fileMonitor
ln -sf /etc/init.d/fileMonitor /etc/rc3.d/S32fileMonitor
ln -sf /etc/init.d/fileMonitor /etc/rc4.d/S32fileMonitor
ln -sf /etc/init.d/fileMonitor /etc/rc5.d/S32fileMonitor
ln -sf /etc/init.d/fileMonitor /etc/rc6.d/K28fileMonitor
#chkconfig --add fileMonitor 
