from flask_mysql_connector import MySQL

mysql = MySQL()

def init_db(app):
    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'tracker_user'
    app.config['MYSQL_PASSWORD'] = 'Umesh123'
    app.config['MYSQL_DATABASE'] = 'tracker'

    mysql.init_app(app)
    return mysql