from ca_api import app

if __name__ == "__main__":
    
    # Connect app logger to wsgi server logger and start app
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    app.run()