from flask_restful import Resource, reqparse, fields, marshal_with
from flask_login import login_required, current_user , login_user, logout_user
from flask import session
from .models import User, Vulnerability, Subscription
from . import db,mailing

from sqlalchemy import or_

import json
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, extract, desc, distinct

from datetime import datetime
# from .utils.Mail import welcome_email,unsubscribed_email

import threading


login_parser = reqparse.RequestParser()
login_parser.add_argument('email', type=str, required=True)
login_parser.add_argument('password', type=str, required=True)

class LoginResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()
        user = User.query.filter_by(email=args['email']).first()
        if user and user.check_password(args['password']):
            login_user(user)
            session['role'] = user.role  # Stocker le rôle dans la session
            return {
                'message': 'Login successful',
                'data' : {
                    "role" : user.role
                }
                }, 200
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

    @login_required
    def put(self, vulnerability_id):
        if session.get('role') != 'editor':
            return {'message': 'Unauthorized'}, 403

        parser = reqparse.RequestParser()
        parser.add_argument('cve_id', type=str)
        parser.add_argument('titre', type=str)
        parser.add_argument('description', type=str)
        # parser.add_argument('date_published', type=str)
        # parser.add_argument('last_modified', type=str)
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
        # parser.add_argument('status', type=str)
        args = parser.parse_args()

        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        for key, value in args.items():
            if value is not None:
                setattr(vulnerability, key, value)
        vulnerability.status = "valide"
        db.session.commit()
        
        return {}, 200

    @login_required
    def delete(self, vulnerability_id):
        # if session.get('role') != 'admin':
        #     return {'message': 'Unauthorized'}, 403

        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        db.session.delete(vulnerability)
        db.session.commit()
        return '', 204


class RandomVulnerabilitiesResource(Resource):
    @marshal_with(vulnerability_fields)
    def get(self):
        # Query 3 random CVEs from the database
        random_vulnerabilities = Vulnerability.query.filter(Vulnerability.type != 'Unknown').order_by(func.random()).limit(3).all()

        # If no vulnerabilities are found, return a 404 error
        if not random_vulnerabilities:
            return {'message': 'No vulnerabilities found'}, 404

        # Serialize the results
        

        return [
            {
                'cve_id' : vuln.cve_id,
                'type' : vuln.type,
                'description' : vuln.description
            } for vuln in random_vulnerabilities], 200

class VulnerabilityRejectResource(Resource):
    @login_required
    def put(self, vulnerability_id):
        vulnerability = Vulnerability.query.get_or_404(vulnerability_id)
        if vulnerability.status == "valide" :
            vulnerability.status = "rejetee"
            db.session.commit()
            return '', 204
        return '', 403
        

# class VulnerabilityListResource(Resource):
#     @marshal_with(vulnerability_fields)
#     def get(self):
#         vulnerabilities = Vulnerability.query.all()
#         return vulnerabilities, 200
    

class VulnerabilityListResource(Resource):
    # @marshal_with(vulnerability_fields)
    @login_required
    def get(self):
        # Récupérer les paramètres de pagination sans exiger JSON
        parser = reqparse.RequestParser()
        parser.add_argument('page', type=int, default=1, help='Numéro de la page', location='args')
        parser.add_argument('per_page', type=int, default=10, help='Nombre de résultats par page', location='args')
        parser.add_argument('status', type=str, default=None, help='Status des CVEs', location='args')
        parser.add_argument('search', type=str, default=None, help='Rechercher par CVE ID, type ou tags', location='args')
        args = parser.parse_args()  # Parse les arguments de la requête (query parameters)

        page = args['page']
        per_page = args['per_page']
        status = args['status']
        search = args['search']

        # Construire la requête de base
        query = Vulnerability.query

        # Appliquer un filtre de statut si spécifié
        if status is not None:
            query = query.filter(Vulnerability.status.in_([status, "rejetee"]))

        # Appliquer un filtre de recherche si spécifié
        if search:
            query = query.filter(
                or_(
                    Vulnerability.cve_id.ilike(f'%{search}%'),
                    Vulnerability.type.ilike(f'%{search}%'),
                    Vulnerability.tags.ilike(f'%{search}%')
                )
            )

        # Récupérer les vulnérabilités paginées
        vulnerabilities = query.order_by(desc(Vulnerability.date_published)).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        # Calculer les statistiques
        total_cves = Vulnerability.query.count()
        verified_cves = Vulnerability.query.filter_by(status="valide").count()

        # Calculer les nouvelles CVEs pour le mois en cours
        current_month = datetime.now().month
        current_year = datetime.now().year
        monthly_new_cves = Vulnerability.query.filter(
            extract('year', Vulnerability.date_published) == current_year,
            extract('month', Vulnerability.date_published) == current_month
        ).count()

        # Retourner les résultats paginés
        return {
            'data': [vuln.to_dict() for vuln in vulnerabilities.items],
            'page': vulnerabilities.page,
            'per_page': vulnerabilities.per_page,
            'total_pages': vulnerabilities.pages,
            'total_items': vulnerabilities.total,
            'stats': {
                'total_cves': total_cves,
                'verified_cves': verified_cves,
                'monthly_new_cves': monthly_new_cves
            }
        }, 200
class VulnerabilityDiscoverResource(Resource):
    # @marshal_with(vulnerability_fields)
    
    def get(self):
        # Récupérer les paramètres de pagination sans exiger JSON
        parser = reqparse.RequestParser()
        parser.add_argument('page', type=int, default=1, help='Numéro de la page', location='args')
        parser.add_argument('per_page', type=int, default=10, help='Nombre de résultats par page', location='args')
        # parser.add_argument('status', type=str, default=None, help='Status des CVEs', location='args')
        parser.add_argument('search', type=str, default=None, help='Rechercher par CVE ID, type ou tags', location='args')
        args = parser.parse_args()  # Parse les arguments de la requête (query parameters)

        page = args['page']
        per_page = args['per_page']
        # status = args['status']
        search = args['search']

        # Construire la requête de base
        query = Vulnerability.query

        # Appliquer un filtre de statut si spécifié
        # if status is not None:
        query = query.filter(Vulnerability.status.in_(['valide']))

        # Appliquer un filtre de recherche si spécifié
        if search:
            query = query.filter(
                or_(
                    Vulnerability.cve_id.ilike(f'%{search}%'),
                    Vulnerability.type.ilike(f'%{search}%'),
                    Vulnerability.tags.ilike(f'%{search}%')
                )
            )

        # Récupérer les vulnérabilités paginées
        vulnerabilities = query.order_by(desc(Vulnerability.date_published)).paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        # Calculer les statistiques
        total_cves = Vulnerability.query.count()
        verified_cves = Vulnerability.query.filter_by(status="valide").count()

        # Calculer les nouvelles CVEs pour le mois en cours
        current_month = datetime.now().month
        current_year = datetime.now().year
        monthly_new_cves = Vulnerability.query.filter(
            extract('year', Vulnerability.date_published) == current_year,
            extract('month', Vulnerability.date_published) == current_month
        ).count()

        # Retourner les résultats paginés
        return {
            'data': [vuln.to_dict() for vuln in vulnerabilities.items],
            'page': vulnerabilities.page,
            'per_page': vulnerabilities.per_page,
            'total_pages': vulnerabilities.pages,
            'total_items': vulnerabilities.total,
            'stats': {
                'total_cves': total_cves,
                'verified_cves': verified_cves,
                'monthly_new_cves': monthly_new_cves
            }
        }, 200

class SubscriptionResource(Resource):
    
    @marshal_with(subscription_fields)
    def get(self, subscription_id):
        subscription = Subscription.query.get_or_404(subscription_id)
        return subscription

    def post(self):
        try :
            parser = reqparse.RequestParser()
            parser.add_argument('email', type=str, required=True)
            parser.add_argument('cve_types', type=str, required=True)
            args = parser.parse_args()

            subscription = Subscription(email=args['email'], cve_types=args['cve_types'])
            session["subscription"] = subscription.id
            db.session.add(subscription)
            db.session.commit()

            
            threading.Thread(target=mailing.welcome_email, args=(args['email'],)).start()
            return subscription.to_dict(), 201
        except IntegrityError  :
            return 'Email already subscribed.', 403
        except Exception as e:
            # Log the error for debugging purposes
            print(f"Internal Server Error: {e}")
            return 'Internal Server Error', 500

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
    
    def put(self):
        sub = session.get("subscription")
        if sub:
            parser = reqparse.RequestParser()
            parser.add_argument('email', type=str)
            parser.add_argument('cve_types', type=str)
            args = parser.parse_args()

            subscription = Subscription.query.get_or_404(sub['id'])
            for key, value in args.items():
                if value is not None:
                    setattr(subscription, key, value)
            db.session.commit()
            return subscription, 200
        else:
            return {'message': 'Unauthorized'}, 401

    
    # @login_required
    # def delete(self):
    #     sub = session.get("subscription")
    #     if sub:
    #         subscription = Subscription.query.get_or_404(sub['id'])
    #         db.session.delete(subscription)
    #         db.session.commit()
    #         threading.Thread(target=unsubscribed_email, args=(subscription.email,)).start()
    #         return '', 204
    #     else:
    #          return {'message': 'Please unsubscribe from the email we sent you.'}, 404

    def delete(self,subscription_id):
        subscription = Subscription.query.get_or_404(subscription_id)
        db.session.delete(subscription)
        db.session.commit()
        threading.Thread(target=unsubscribed_email, args=(subscription.email,)).start()
        return '', 204



class SubscriptionListResource(Resource):
    @marshal_with(subscription_fields)
    def get(self):
        subscriptions = Subscription.query.all()
        return subscriptions, 200

class AdminListResource(Resource):
    @marshal_with(user_fields)
    def get(self):
        if session.get('role') != 'super-admin':
            return {'message': 'Unauthorized'}, 403
        admins = User.query.filter(
                User.role.in_(['admin','editor'])
            ).all()
        return admins, 200
    
class GraphDataResource(Resource):
    def get(self):
        # Parse the query parameter for the graph type
        parser = reqparse.RequestParser()
        parser.add_argument('type', type=int, required=True, help='Graph type is required (1, 2, or 3)', location='args')
        args = parser.parse_args()

        graph_type = args['type']

        if graph_type == 1:
            # Graph 1: Vulnerabilities by type of software affected
            data = self._get_vulnerabilities_by_software()
        elif graph_type == 2:
            # Graph 2: Vulnerabilities by severity level
            data = self._get_cve_count_per_month()
        elif graph_type == 3:
            # Graph 3: Vulnerabilities by status
            data = self._get_cve_by_type()
        elif graph_type == 4:
            # Graph 3: Vulnerabilities by status
            data = self._get_cve_by_platform()
        else:
            return {'message': 'Invalid graph type. Use 1, 2, or 3.'}, 400

        return {'data': data}, 200

    def _get_vulnerabilities_by_software(self):
        # Group vulnerabilities by affected_software and count them
        result = (
            db.session.query(Vulnerability.affected_software, func.count(Vulnerability.id))
            .filter(Vulnerability.affected_software != 'Unknown')
            .group_by(Vulnerability.affected_software)
            .all()
        )
        return [{'software': software, 'count': count} for software, count in result]

    def _get_cve_count_per_month(self):
        import calendar
        from datetime import datetime, timedelta

        # Get the current date
        current_date = datetime.now()

        # Generate a list of the last 12 months
        last_12_months = []
        for i in range(11):
            # Calculate the date for the current iteration (going back in time)
            target_date = current_date - timedelta(days=30 * i)
            year = target_date.year
            month = target_date.month
            month_name = calendar.month_name[month]
            last_12_months.append({
                'year': year,
                'month': month,
                'month_name': month_name,
                'count': 0  # Initialize count to 0
            })

        # Reverse the list to start from the oldest month to the current month
        last_12_months.reverse()

        # Query the database for CVE counts per month within the last 12 months
        result = (
            db.session.query(
                extract('year', Vulnerability.date_published).label('year'),
                extract('month', Vulnerability.date_published).label('month'),
                func.count(Vulnerability.id).label('count')
            )
            .filter(
                Vulnerability.date_published >= (current_date - timedelta(days=365))  # Filter for the last 12 months
            )
            .group_by('year', 'month')
            .order_by('year', 'month')
            .all()
        )

        # Merge the database results with the last_12_months list
        for db_row in result:
            year, month, count = db_row
            # Find the corresponding month in the last_12_months list and update its count
            for entry in last_12_months:
                if entry['year'] == year and entry['month'] == month:
                    entry['count'] = count
                    break

        return last_12_months

    def _get_cve_by_type(self):
        # Group vulnerabilities by type and count them
        result = (
            db.session.query(Vulnerability.type, func.count(Vulnerability.id))
            .filter(Vulnerability.type != 'Unknown')
            .group_by(Vulnerability.type)
            .all()
        )
        return [{'type': type_, 'count': count} for type_, count in result]
    
    def _get_cve_by_platform(self):
        # Group vulnerabilities by type and count them
        result = (
            db.session.query(Vulnerability.platform, func.count(Vulnerability.id))
            .filter(Vulnerability.platform != 'Unknown')
            .group_by(Vulnerability.platform)
            .all()
        )
        return [{'type': type_, 'count': count} for type_, count in result]


class CveTypesResource(Resource):
    def get(self):
        # Query distinct CVE types from the Vulnerability model
        distinct_types = db.session.query(distinct(Vulnerability.type)).filter(Vulnerability.type != 'Unknown').all()

        # Extract the types from the query result
        cve_types = [type_[0] for type_ in distinct_types]

        return {'cve_types': cve_types}, 200



