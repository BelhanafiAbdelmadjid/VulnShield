from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_login import LoginManager
from flask_admin import Admin
from flask_restful import Api
from flask_admin.contrib.sqla import ModelView
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger 
from .utils.Mail import Mailing




db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
login_manager = LoginManager()
admin = Admin(name='Vulnerability Monitor', template_mode='bootstrap3')
api = Api()
mailing = Mailing()

scheduler = BackgroundScheduler()
from .scheduler import send_weekly_cve_emails

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    login_manager.init_app(app)
    admin.init_app(app)
    api.init_app(app)

    

    from .models import User, Vulnerability, Subscription
    from .routes import main

    admin.add_view(ModelView(User, db.session))
    admin.add_view(ModelView(Vulnerability, db.session))
    admin.add_view(ModelView(Subscription, db.session))

    app.register_blueprint(main)

    # with app.app_context():
    scheduler = BackgroundScheduler()
    
    scheduler.add_job(send_weekly_cve_emails, IntervalTrigger(minutes=60), args=[app,mailing])

    from .utils.VeilleAuto import veille
    from .models import Vulnerability
    scheduler.add_job(
        func=veille,
        # trigger=IntervalTrigger(hours=12),
        trigger=IntervalTrigger(hours=12),
        id='scrape_sources',
        replace_existing=True,
        coalesce=True,  # Prevent overlapping executions
        max_instances=1,
        args=[app,Vulnerability]
    )

    scheduler.start()

    veille(app,Vulnerability)
        
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    return app

def create_admin_user(app):
    from .models import User
    with app.app_context():
        admin_email = 'belhanafiabdelmadjid@gmail.com'
        admin_password = 'adminpassword'
        admin_role = 'admin'

        if not User.query.filter_by(email=admin_email).first():
            admin_user = User(email=admin_email, role=admin_role)
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print(f'Admin user {admin_email} created successfully.')
        else:
            print(f'Admin user {admin_email} already exists.')
def create_test_cves(app):
    from .models import Vulnerability
    with app.app_context():
        test_cves = [
            {'cve_id': 'CVE-2023-1234', 'description': 'Test vulnerability 1', 'source': 'NVD', 'status': 'pending'},
            {'cve_id': 'CVE-2023-1235', 'description': 'Test vulnerability 2', 'source': 'NVD', 'status': 'pending'},
            {'cve_id': 'CVE-2023-1236', 'description': 'Test vulnerability 3', 'source': 'NVD', 'status': 'pending'},
        ]

        for cve in test_cves:
            if not Vulnerability.query.filter_by(cve_id=cve['cve_id']).first():
                new_cve = Vulnerability(**cve)
                db.session.add(new_cve)
                db.session.commit()
                print(f'CVE {cve["cve_id"]} created successfully.')
            else:
                print(f'CVE {cve["cve_id"]} already exists.')