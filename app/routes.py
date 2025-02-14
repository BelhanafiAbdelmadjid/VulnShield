from flask import Blueprint,render_template
from flask_restful import Api
from .resources import CveTypesResource, GraphDataResource,RandomVulnerabilitiesResource,VulnerabilityResource, VulnerabilityListResource, SubscriptionResource, SubscriptionListResource,LoginResource,LogoutResource,AdminListResource,VulnerabilityRejectResource,VulnerabilityDiscoverResource

main = Blueprint('main', __name__)
api = Api(main)

# api.add_resource(UserResource, '/users/<int:user_id>')

# ------------------------ Vulnerabilities management ------------------------ #
api.add_resource(VulnerabilityResource, '/vulnerability/<int:vulnerability_id>', endpoint='vulnerability', methods=['GET', 'PUT', 'DELETE'])
api.add_resource(VulnerabilityRejectResource, '/vulnerability/<int:vulnerability_id>/reject/', endpoint='vulnerability_rejection', methods=['PUT'])
api.add_resource(VulnerabilityListResource, '/vulnerabilities', endpoint='vulnerabilities', methods=['GET'])
api.add_resource(VulnerabilityDiscoverResource, '/discover', endpoint='discover', methods=['GET'])
api.add_resource(RandomVulnerabilitiesResource, '/discover/random', endpoint='discover-random', methods=['GET'])
api.add_resource(GraphDataResource, '/graph', endpoint='graph-data', methods=['GET'])
api.add_resource(CveTypesResource, '/cves/types', endpoint='types', methods=['GET'])

# ------------------------------- Subscriptions ------------------------------ #
api.add_resource(SubscriptionResource, '/subscriptions/<int:subscription_id>', endpoint='subscription', methods=['GET', 'PUT', 'DELETE'])
api.add_resource(SubscriptionResource, '/subscriptions', endpoint='subscriptions_post', methods=['POST'])
api.add_resource(SubscriptionListResource, '/subscriptions', endpoint='subscriptions', methods=['GET'])

# ----------------------------------- Auth ----------------------------------- #
api.add_resource(LoginResource, '/login', endpoint='login', methods=['POST'])
api.add_resource(LogoutResource, '/logout', endpoint='logout', methods=['POST'])

# ----------------------------------- Admin ----------------------------------- #
api.add_resource(AdminListResource, '/admins', endpoint='admins', methods=['GET'])

# from flask import Blueprint, render_template, redirect, url_for, flash, request
# from flask_login import login_user, logout_user, login_required, current_user
# from .forms import LoginForm, SubscriptionForm
# from .models import User, Vulnerability, Subscription
# from . import db

# main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

# @main.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user and user.check_password(form.password.data):
#             login_user(user)
#             return redirect(url_for('main.dashboard'))
#         else:
#             flash('Invalid email or password', 'danger')
#     return render_template('login.html', form=form)

# @main.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     return redirect(url_for('main.index'))

# @main.route('/dashboard')
# @login_required
# def dashboard():
#     if current_user.role == "admin" : 
#         vulnerabilities = Vulnerability.query.all()
#     elif current_user.role == 'scraper':
#         vulnerabilities = Vulnerability.query.filter_by(status='pending').all()
#     elif current_user.role == 'text_processor':
#         vulnerabilities = Vulnerability.query.filter_by(status='scraped').all()
#     elif current_user.role == 'analyst':
#         vulnerabilities = Vulnerability.query.filter_by(status='processed').all()
#     else:
#         vulnerabilities = []
#     return render_template('dashboard.html', vulnerabilities=vulnerabilities)

# @main.route('/subscribe', methods=['GET', 'POST'])
# def subscribe():
#     form = SubscriptionForm()
#     if form.validate_on_submit():
#         subscription = Subscription(email=form.email.data, cve_types=','.join(form.cve_types.data))
#         db.session.add(subscription)
#         db.session.commit()
#         flash('Subscription successful!', 'success')
#         return redirect(url_for('main.index'))
#     return render_template('subscribe.html', form=form)

# @main.route('/validate/<int:vulnerability_id>', methods=['POST'])
# @login_required
# def validate_vulnerability(vulnerability_id):
#     vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
#     if current_user.role == 'scraper' and vulnerability.status == 'pending':
#         vulnerability.status = 'scraped'
#     elif current_user.role == 'text_processor' and vulnerability.status == 'scraped':
#         vulnerability.status = 'processed'
#     elif current_user.role == 'analyst' and vulnerability.status == 'processed':
#         vulnerability.status = 'validated'
#     db.session.commit()
#     flash('Vulnerability validated!', 'success')
#     return redirect(url_for('main.dashboard'))
