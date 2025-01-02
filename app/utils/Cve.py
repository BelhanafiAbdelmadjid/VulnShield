from app.models import Vulnerability
from app import db
from app import create_app

def update_or_insert_vulnerabilities(vulnerabilities):
    for vuln in vulnerabilities:
        existing_vuln = Vulnerability.query.filter_by(cve_id=vuln['CVE_ID']).first()
        if existing_vuln:
            print("update")
            # Mettre à jour les champs qui sont null dans la base de données
            for key, value in vuln.items():
                if value is not None and value != "N/A" and getattr(existing_vuln, key.lower()) is None:
                    setattr(existing_vuln, key.lower(), value)
            existing_vuln.status = "brut"  
            db.session.commit()
        else:
            # Insérer une nouvelle vulnérabilité
            new_vuln = Vulnerability(
                cve_id=vuln['CVE_ID'] if (vuln['CVE_ID'] is not None and vuln['CVE_ID'] != "N/A") else None,
                titre=vuln['Titre'] if (vuln['Titre'] is not None and vuln['Titre'] != "N/A") else None,
                description=vuln['Description'] if (vuln['Description'] is not None and vuln['Description'] != "N/A") else None,
                date_published=vuln['Date_Published'] if (vuln['Date_Published'] is not None and vuln['Date_Published'] != "N/A") else None,
                last_modified=vuln['Last_Modified'] if (vuln['Last_Modified'] is not None and vuln['Last_Modified'] != "N/A") else None,
                type=vuln['Type'] if (vuln['Type'] is not None and vuln['Type'] != "N/A") else None,
                platform=vuln['Platform'] if (vuln['Platform'] is not None and vuln['Platform'] != "N/A") else None,
                author=vuln['Author'] if (vuln['Author'] is not None and vuln['Author'] != "N/A") else None,
                severity=vuln['Severity'] if (vuln['Severity'] is not None and vuln['Severity'] != "N/A") else None,
                references="/*/".join(vuln['References']) if vuln['References'] else None,
                # references_list=None,
                cvss=vuln['CVSS'] if (vuln['CVSS'] is not None and vuln['CVSS'] != "N/A") else None,
                created=vuln['Created'] if (vuln['Created'] is not None and vuln['Created'] != "N/A") else None,
                added=vuln['Added'] if (vuln['Added'] is not None and vuln['Added'] != "N/A") else None,
                solutions=vuln['Solutions'] if (vuln['Solutions'] is not None and vuln['Solutions'] != "N/A") else None,
                verified=vuln['verified'] if (vuln['verified'] is not None and vuln['verified'] != "N/A") else None,
                application_path=vuln['application_path'] if (vuln['application_path'] is not None and vuln['application_path'] != "N/A") else None,
                application_md5=vuln['application_md5'] if (vuln['application_md5'] is not None and vuln['application_md5'] != "N/A") else None,
                base_score=vuln['Base_Score'] if (vuln['Base_Score'] is not None and vuln['Base_Score'] != "N/A") else None,
                attack_vector=vuln['Attack_Vector'] if (vuln['Attack_Vector'] is not None and vuln['Attack_Vector'] != "N/A") else None,
                attack_complexity=vuln['Attack_Complexity'] if (vuln['Attack_Complexity'] is not None and vuln['Attack_Complexity'] != "N/A") else None,
                privileges_required=vuln['Privileges_Required'] if (vuln['Privileges_Required'] is not None and vuln['Privileges_Required'] != "N/A") else None,
                user_interaction=vuln['User_Interaction'] if (vuln['User_Interaction'] is not None and vuln['User_Interaction'] != "N/A") else None,
                scope=vuln['Scope'] if (vuln['Scope'] is not None and vuln['Scope'] != "N/A") else None,
                exploitability_score=vuln['Exploitability_Score'] if (vuln['Exploitability_Score'] is not None and vuln['Exploitability_Score'] != "N/A") else None,
                impact_score=vuln['Impact_Score'] if (vuln['Impact_Score'] is not None and vuln['Impact_Score'] != "N/A") else None,
                confidentiality_impact=vuln['Confidentiality_Impact'] if (vuln['Confidentiality_Impact'] is not None and vuln['Confidentiality_Impact'] != "N/A") else None,
                integrity_impact=vuln['Integrity_Impact'] if (vuln['Integrity_Impact'] is not None and vuln['Integrity_Impact'] != "N/A") else None,
                availability_impact=vuln['Availability_Impact'] if (vuln['Availability_Impact'] is not None and vuln['Availability_Impact'] != "N/A") else None,
                affected_software=vuln['Affected_Software'] if (vuln['Affected_Software'] is not None and vuln['Affected_Software'] != "N/A") else None,
                tags=vuln['tags'] if (vuln['tags'] is not None and vuln['tags'] != "N/A") else None,
                status='brut'
            )
            db.session.add(new_vuln)
            db.session.commit()


# Example usage for testing
if __name__ == "__main__":
    # Example list of scraped vulnerabilities
    from .Scrap.ExploitDB import ExploitDBScraper
    scraper = ExploitDBScraper()
    res = scraper.scrape_exploits(12, "months")

    with create_app().app_context():
        update_or_insert_vulnerabilities(res)