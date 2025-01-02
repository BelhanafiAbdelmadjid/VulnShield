import unittest
from app.utils.Scrap.mitre import ExploitDBScraper
from app.utils.Cve import update_or_insert_vulnerabilities

class TestScrap(unittest.TestCase):
    
    def test_mitre_fill_full_scrap(self):
        # scraper = ExploitDBScraper()
        # res = scraper.scrape_exploits(0, None)
        # update_or_insert_vulnerabilities(res)

       


if __name__ == '__main__':
    unittest.main()