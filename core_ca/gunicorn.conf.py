# gunicorn.conf.py
# Non logging stuff
# Application is served to nginx server through unix socket
bind = "unix:core_ca.sock"
workers = 3
#umask = "007"
# Access log - records incoming HTTP requests
accesslog = "/home/vagrant/core_ca/log/gunicorn.access.log"
# Error log - records Gunicorn server goings-on
errorlog = "/home/vagrant/core_ca/log/gunicorn.error.log"
# Whether to send Flask output to the error log 
capture_output = True
# How verbose the Gunicorn error logs should be 
loglevel = "info"
