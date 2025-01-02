from app import db,mailing
from .models import Subscription
# from .utils import weekly_cve_email


def get_all_users():
    return db.session.query(Subscription.email, Subscription.id).all()

def send_weekly_cve_emails(app,mailing):
    print("SENDING WEKKLY EMAIL")
    with app.app_context():
        users = get_all_users()
    for user in users:
        # to_email = user['email']
        print(user[0],user[1])
        cve_list = [
            {'id': 'CVE-2023-1234', 'description': 'Description of CVE-2023-1234'},
            {'id': 'CVE-2023-5678', 'description': 'Description of CVE-2023-5678'},
            {'id': 'CVE-2023-9101', 'description': 'Description of CVE-2023-9101'},
            {'id': 'CVE-2023-1112', 'description': 'Description of CVE-2023-1112'},
            {'id': 'CVE-2023-1314', 'description': 'Description of CVE-2023-1314'}
        ]
        mailing.weekly_cve_email(user[0],user[1], cve_list)



