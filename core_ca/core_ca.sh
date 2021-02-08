#! /bin/sh
### BEGIN INIT INFO
# Provides:          core_ca
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start daemon at boot time
# Description:       Enable service provided by daemon.
### END INIT INFO
# /etc/init.d/core_ca
 
case "$1" in
  start)
    echo "Starting Core CA API"
    # run application you want to start
    cd /home/vagrant/core_ca
    /usr/local/bin/gunicorn -c /home/vagrant/core_ca/gunicorn.conf.py wsgi:app &
    cd /home/vagrant
    ;;
  stop)
    echo "Stopping Core CA API"
    # kill application you want to stop
    killall gunicorn
    killall python3
    ;;
  *)
    echo "Usage: /etc/init.d/core_ca{start|stop}"
    exit 1
    ;;
esac
 
exit 0