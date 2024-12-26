from flask_restful import Resource, reqparse, fields, marshal_with
from flask_login import login_required, current_user , login_user, logout_user
from .models import User, Vulnerability, Subscription
from . import db


login_parser = reqparse.RequestParser()
login_parser.add_argument('email', type=str, required=True)
login_parser.add_argument('password', type=str, required=True)

class LoginResource(Resource):
    def post(self):
        args = login_parser.parse_args()
        user = User.query.filter_by(email=args['email']).first()
        if user and user.check_password(args['password']):
            login_user(user)
            return {'message': 'Login successful'}, 200
        else:
            return {'message': 'Invalid email or password'}, 401

class LogoutResource(Resource):
    @login_required
    def post(self):
        logout_user()
        return {'message': 'Logout successful'}, 200


user_fields = {
    'id': fields.Integer,
    'email': fields.String,
    'role': fields.String
}

vulnerability_fields = {
    'id': fields.Integer,
    'cve_id': fields.String,
    'titre': fields.String,
    'description': fields.String,
    'date_published': fields.DateTime,
    'last_modified': fields.DateTime,
    'type': fields.String,
    'platform': fields.String,
    'author': fields.String,
    'severity': fields.String,
    'references_list': fields.String,
    'cvss': fields.String,
    'created': fields.DateTime,
    'added': fields.DateTime,
    'solutions': fields.String,
    'verified': fields.Boolean,
    'application_path': fields.String,
    'application_md5': fields.String,
    'base_score': fields.Float,
    'attack_vector': fields.String,
    'attack_complexity': fields.String,
    'privileges_required': fields.String,
    'user_interaction': fields.String,
    'scope': fields.String,
    'exploitability_score': fields.Float,
    'impact_score': fields.Float,
    'confidentiality_impact': fields.String,
    'integrity_impact': fields.String,
    'availability_impact': fields.String,
    'affected_software': fields.String,
    'tags': fields.String,
    'screenshot_path': fields.String,
    'screenshot_thumb_path': fields.String,
    'status': fields.String
}

subscription_fields = {
    'id': fields.Integer,
    'email': fields.String,
    'cve_types': fields.String
}

# class UserResource(Resource):
#     @marshal_with(user_fields)
#     def get(self, user_id):
#         user = User.query.get_or_404(user_id)
#         return user

class VulnerabilityResource(Resource):
    @marshal_with(vulnerability_fields)
    def get(self, vulnerability_id):
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        return vulnerability

    # @login_required
    # def post(self):
    #     parser = reqparse.RequestParser()
    #     parser.add_argument('cve_id', type=str, required=True)
    #     parser.add_argument('titre', type=str)
    #     parser.add_argument('description', type=str, required=True)
    #     parser.add_argument('date_published', type=str)
    #     parser.add_argument('last_modified', type=str)
    #     parser.add_argument('type', type=str)
    #     parser.add_argument('platform', type=str)
    #     parser.add_argument('author', type=str)
    #     parser.add_argument('severity', type=str)
    #     parser.add_argument('references_list', type=str)
    #     parser.add_argument('cvss', type=str)
    #     parser.add_argument('created', type=str)
    #     parser.add_argument('added', type=str)
    #     parser.add_argument('solutions', type=str)
    #     parser.add_argument('verified', type=bool)
    #     parser.add_argument('application_path', type=str)
    #     parser.add_argument('application_md5', type=str)
    #     parser.add_argument('base_score', type=float)
    #     parser.add_argument('attack_vector', type=str)
    #     parser.add_argument('attack_complexity', type=str)
    #     parser.add_argument('privileges_required', type=str)
    #     parser.add_argument('user_interaction', type=str)
    #     parser.add_argument('scope', type=str)
    #     parser.add_argument('exploitability_score', type=float)
    #     parser.add_argument('impact_score', type=float)
    #     parser.add_argument('confidentiality_impact', type=str)
    #     parser.add_argument('integrity_impact', type=str)
    #     parser.add_argument('availability_impact', type=str)
    #     parser.add_argument('affected_software', type=str)
    #     parser.add_argument('tags', type=str)
    #     parser.add_argument('screenshot_path', type=str)
    #     parser.add_argument('screenshot_thumb_path', type=str)
    #     parser.add_argument('status', type=str)
    #     args = parser.parse_args()

    #     vulnerability = Vulnerability(**args)
    #     db.session.add(vulnerability)
    #     db.session.commit()
    #     return vulnerability, 201

    @login_required
    def put(self, vulnerability_id):
        parser = reqparse.RequestParser()
        parser.add_argument('cve_id', type=str)
        parser.add_argument('titre', type=str)
        parser.add_argument('description', type=str)
        parser.add_argument('date_published', type=str)
        parser.add_argument('last_modified', type=str)
        parser.add_argument('type', type=str)
        parser.add_argument('platform', type=str)
        parser.add_argument('author', type=str)
        parser.add_argument('severity', type=str)
        parser.add_argument('references_list', type=str)
        parser.add_argument('cvss', type=str)
        parser.add_argument('created', type=str)
        parser.add_argument('added', type=str)
        parser.add_argument('solutions', type=str)
        parser.add_argument('verified', type=bool)
        parser.add_argument('application_path', type=str)
        parser.add_argument('application_md5', type=str)
        parser.add_argument('base_score', type=float)
        parser.add_argument('attack_vector', type=str)
        parser.add_argument('attack_complexity', type=str)
        parser.add_argument('privileges_required', type=str)
        parser.add_argument('user_interaction', type=str)
        parser.add_argument('scope', type=str)
        parser.add_argument('exploitability_score', type=float)
        parser.add_argument('impact_score', type=float)
        parser.add_argument('confidentiality_impact', type=str)
        parser.add_argument('integrity_impact', type=str)
        parser.add_argument('availability_impact', type=str)
        parser.add_argument('affected_software', type=str)
        parser.add_argument('tags', type=str)
        parser.add_argument('screenshot_path', type=str)
        parser.add_argument('screenshot_thumb_path', type=str)
        parser.add_argument('status', type=str)
        args = parser.parse_args()

        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        for key, value in args.items():
            if value is not None:
                setattr(vulnerability, key, value)
        db.session.commit()
        return vulnerability, 200

    @login_required
    def delete(self, vulnerability_id):
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        db.session.delete(vulnerability)
        db.session.commit()
        return '', 204

class VulnerabilityListResource(Resource):
    @marshal_with(vulnerability_fields)
    def get(self):
        vulnerabilities = Vulnerability.query.all()
        return vulnerabilities, 200

class SubscriptionResource(Resource):
    @marshal_with(subscription_fields)
    def get(self, subscription_id):
        subscription = Subscription.query.get_or_404(subscription_id)
        return subscription

    @login_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('cve_types', type=str, required=True)
        args = parser.parse_args()

        subscription = Subscription(email=args['email'], cve_types=args['cve_types'])
        db.session.add(subscription)
        db.session.commit()
        return subscription, 201

    @login_required
    def put(self, subscription_id):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str)
        parser.add_argument('cve_types', type=str)
        args = parser.parse_args()

        subscription = Subscription.query.get_or_404(subscription_id)
        for key, value in args.items():
            if value is not None:
                setattr(subscription, key, value)
        db.session.commit()
        return subscription, 200

    @login_required
    def delete(self, subscription_id):
        subscription = Subscription.query.get_or_404(subscription_id)
        db.session.delete(subscription)
        db.session.commit()
        return '', 204

class SubscriptionListResource(Resource):
    @marshal_with(subscription_fields)
    def get(self):
        subscriptions = Subscription.query.all()
        return subscriptions, 200
