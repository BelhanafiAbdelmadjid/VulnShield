from . import db,mail
from flask_mail import Message
from .models import Subscription, Vulnerability

def scrape_vulnerabilities():
    # Placeholder for scraping logic
    # This function will be filled later
    pass


def send_daily_alerts():
    subscriptions = Subscription.query.all()
    for subscription in subscriptions:
        cve_types = subscription.cve_types.split(',')
        vulnerabilities = Vulnerability.query.filter(Vulnerability.cve_id.in_(cve_types)).all()
        if vulnerabilities:
            msg = Message("Daily Vulnerability Alert", recipients=[subscription.email])
            msg.body = "Here are the new vulnerabilities:\n\n" + "\n".join([v.description for v in vulnerabilities])
            mail.send(msg)

