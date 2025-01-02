from .Cve import update_or_insert_vulnerabilities

from .Scrap.ExploitDB import ExploitDBScraper
from .Scrap.Nvd import EnhancedNVDVulnerabilityFetcher

from .TextTraitement import process_all_cves

def veille(app,Vulnerability):
    with app.app_context(): 
        try : 
            scraper = ExploitDBScraper()
            # vuls = scraper.scrape_exploits(12, "hours")
            vuls = scraper.scrape_exploits(12, "hours")
            print("scarpped from Exploit db",len(vuls))
            update_or_insert_vulnerabilities(vuls)
            print("update_or_insert_vulnerabilities from Exploit db",len(vuls))
        except :
            pass
        # ---------------------------------------------------------------------------- #
        try : 
            fetcher = EnhancedNVDVulnerabilityFetcher()
            # vulnerabilities = fetcher.fetch_vulnerabilities(12, "months")
            vulnerabilities = fetcher.fetch_vulnerabilities(12, "hours")
            print("fetched",vulnerabilities[100])
            update_or_insert_vulnerabilities(vulnerabilities)
        except  Exception as e :
            print("Error on EnhancedNVDVulnerabilityFetcher",e)
            pass
        # ---------------------------------------------------------------------------- #
        try : 
            print("process_all_cves from all")
            process_all_cves(Vulnerability.query.filter_by(status="brut").all())
            print("Done process_all_cves")
        except Exception as e :
            print("Error on process_all_cves",e)
            pass
