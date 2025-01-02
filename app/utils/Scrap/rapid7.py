import asyncio
import aiohttp
from bs4 import BeautifulSoup
import json
import re
import logging
from tqdm import tqdm
from datetime import datetime, timedelta
from typing import List, Dict

# fih kolch
# l'utlisation daylo  when u run there's a menu you wil find it to choose what you wanna scrappe okay
# the menu is like this:
# last x hours
# last x days
# last x months
# exit
# so you can choose what you want to scrappe and the number of hours or days or months you want to scrappe
# and then you will find the result in the end of the execution
# and the result will be saved in a file called processed_vulnerabilities.json but i commented the line that save the result in the file
# so you can uncomment it if you want to save the result in the file
# and you can find the result in the console
# and i added a function that display the result in a good way
BASE_URL = "https://www.rapid7.com"
OUTPUT_FILE = "vulnerabilities.json"
PROCESSED_OUTPUT_FILE = "processed_vulnerabilities.json"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
MAX_CONCURRENCY = 10
MAX_EMPTY_PAGES = 3

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


class RapidVulnerabilityScraper:
    def __init__(self, cutoff_date):
        self.session = None
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        self.vulnerabilities = []
        self.cutoff_date = cutoff_date.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        logger.info(
            f"Scraping vulnerabilities published after: {self.cutoff_date.strftime('%d/%m/%Y')}"
        )

    def _parse_date(self, date_str):
        try:
            if not date_str or date_str == "N/A":
                return None
            parsed_date = datetime.strptime(date_str, "%m/%d/%Y")
            return parsed_date.replace(hour=0, minute=0, second=0, microsecond=0)
        except ValueError:
            logger.warning(f"Failed to parse date: {date_str}")
            return None

    def _format_date(self, date_str):
        parsed_date = self._parse_date(date_str)
        if parsed_date is None:
            return "N/A"
        return parsed_date.strftime("%d/%m/%Y")

    def _is_recent_vulnerability(self, published_date):
        parsed_date = self._parse_date(published_date)
        if parsed_date is None:
            return False
        return parsed_date >= self.cutoff_date

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers=HEADERS)
        return self

    async def __aexit__(self, *args):
        await self.session.close()

    def _extract_cve_id(self, title):
        match = re.search(r"(CVE-\d{4}-\d+)", title)
        return match.group(1) if match else "N/A"

    async def _fetch_url(self, url):
        async with self.semaphore:
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        return await response.text()
                    logger.error(f"Failed to fetch {url}: HTTP {response.status}")
                    return None
            except Exception as e:
                logger.error(f"Error fetching {url}: {e}")
                return None

    def _extract_table_data(self, detail_soup):
        table_data = {}
        for header in detail_soup.find_all("header"):
            key = header.text.strip()
            value_div = header.find_next("div", class_="table-cell")
            value = value_div.text.strip() if value_div else "N/A"
            table_data[key] = value
        return table_data

    async def _scrape_details(self, detail_url):
        content = await self._fetch_url(detail_url)
        if not content:
            return None

        soup = BeautifulSoup(content, "html.parser")
        table_data = self._extract_table_data(soup)

        published_date = table_data.get("Published", "N/A")
        if not self._is_recent_vulnerability(published_date):
            return None

        title_tag = soup.find("h3")
        title = title_tag.text.strip() if title_tag else "N/A"
        cve_id = self._extract_cve_id(title)

        description_section = soup.find("div", class_="vulndb__detail-content")
        description = (
            " ".join([p.text.strip() for p in description_section.find_all("p")])
            if description_section
            else "N/A"
        )

        solutions_section = soup.find("section", class_="vulndb__references")
        solutions = (
            [li.text.strip() for li in solutions_section.find_all("li")]
            if solutions_section
            else []
        )

        references_section = soup.find("section", class_="vulndb__related")
        references = (
            [a["href"] for a in references_section.find_all("a", href=True)]
            if references_section
            else []
        )

        return {
            "CVE_ID": cve_id,
            "Titre": title,
            "Description": description,
            "Date_Published": published_date,
            "Last_Modified": table_data.get("Modified", "N/A"),
            "Type": table_data.get("Type", "N/A"),
            "Platform": table_data.get("Platform", "N/A"),
            "Author": table_data.get("Author", "Rapid7"),
            "Severity": table_data.get("Severity", "N/A"),
            "References": references,
            "CVSS": table_data.get("CVSS", "N/A"),
            "Created": table_data.get("Created", "N/A"),
            "Added": table_data.get("Added", "N/A"),
            "Solutions": solutions,
            "verified": table_data.get("Verified", "false"),
            "application_path": "N/A",
            "application_md5": "N/A",
            "Base_Score": table_data.get("Base Score", "N/A"),
            "Attack_Vector": table_data.get("Attack Vector", "N/A"),
            "Attack_Complexity": table_data.get("Attack Complexity", "N/A"),
            "Privileges_Required": table_data.get("Privileges Required", "N/A"),
            "User_Interaction": table_data.get("User Interaction", "N/A"),
            "Scope": table_data.get("Scope", "N/A"),
            "Exploitability_Score": table_data.get("Exploitability Score", "N/A"),
            "Impact_Score": table_data.get("Impact Score", "N/A"),
            "Confidentiality_Impact": table_data.get("Confidentiality Impact", "N/A"),
            "Integrity_Impact": table_data.get("Integrity Impact", "N/A"),
            "Availability_Impact": table_data.get("Availability Impact", "N/A"),
            "Affected_Software": (
                table_data.get("Affected Software", "").split(", ")
                if table_data.get("Affected Software")
                else []
            ),
            "tags": (
                table_data.get("Tags", "").split(", ") if table_data.get("Tags") else []
            ),
            "screenshot_path": "N/A",
            "screenshot_thumb_path": "N/A",
        }

    async def _scrape_page(self, page_number):
        page_url = f"{BASE_URL}/db/?q=&type=&page={page_number}"
        content = await self._fetch_url(page_url)

        if not content:
            return []

        soup = BeautifulSoup(content, "html.parser")
        detail_links = [
            BASE_URL + link.get("href")
            for link in soup.find_all("a", class_="vulndb__result")
        ]

        if not detail_links:
            return []

        tasks = [self._scrape_details(link) for link in detail_links]
        details = await asyncio.gather(*tasks)
        return [detail for detail in details if detail]

    async def scrape_vulnerabilities(self, start_page=1):
        current_page = start_page
        empty_pages_count = 0

        with tqdm(desc="Scraping pages") as pbar:
            while empty_pages_count < MAX_EMPTY_PAGES:
                vulnerabilities = await self._scrape_page(current_page)

                if vulnerabilities:
                    self.vulnerabilities.extend(vulnerabilities)
                    empty_pages_count = 0
                    logger.info(
                        f"Page {current_page}: {len(vulnerabilities)} vulnerabilities found"
                    )
                else:
                    empty_pages_count += 1
                    logger.info(f"Page {current_page}: No recent vulnerabilities found")

                current_page += 1
                pbar.update(1)
                pbar.set_description(
                    f"Scraping pages (Total: {len(self.vulnerabilities)})"
                )

        return self.vulnerabilities

    def save_vulnerabilities(self):
        # Commented out JSON saving functionality
        # with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        #     json.dump(self.vulnerabilities, f, indent=2, ensure_ascii=False)
        logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")


def process_vulnerability_attributes(vulnerabilities: List[Dict]) -> List[Dict]:
    processed_vulns = []
    list_fields = ["References", "Solutions", "Affected_Software", "tags"]

    for vuln in vulnerabilities:
        processed_vuln = {}
        for key, value in vuln.items():
            if key in list_fields:
                if isinstance(value, str):
                    processed_vuln[key] = value.split("; ") if value != "N/A" else []
                else:
                    processed_vuln[key] = value if value != "N/A" else []
            else:
                processed_vuln[key] = value
        processed_vulns.append(processed_vuln)

    return processed_vulns


def save_processed_vulnerabilities(processed_vulns: List[Dict]):
    # Commented out JSON saving functionality
    # with open(PROCESSED_OUTPUT_FILE, "w", encoding="utf-8") as f:
    #     json.dump(processed_vulns, f, indent=2, ensure_ascii=False)
    logger.info(f"Processed {len(processed_vulns)} vulnerabilities")


def display_vulnerability(vuln: Dict):
    json_str = json.dumps(vuln, indent=4)
    print(json_str)
    print()


def get_cutoff_date():
    print("Choose time range to fetch CVEs:")
    print("1. Last X hours")
    print("2. Last X days")
    print("3. Last X months")
    print("4. Exit")

    try:
        choice = int(input("Enter your choice (1-4): "))
        if choice == 4:
            print("Exiting...")
            exit()

        amount = int(input("Enter the number of units (e.g., hours, days, months): "))
        current_date = datetime.now()

        if choice == 1:
            return current_date - timedelta(hours=amount)
        elif choice == 2:
            cutoff = current_date - timedelta(days=amount)
            return cutoff.replace(hour=0, minute=0, second=0, microsecond=0)
        elif choice == 3:
            cutoff = current_date - timedelta(days=amount * 30)
            return cutoff.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            print("Invalid choice. Exiting...")
            exit()
    except ValueError:
        print("Invalid input. Exiting...")
        exit()


async def main():
    cutoff_date = get_cutoff_date()
    print(cutoff_date)
    # async with RapidVulnerabilityScraper(cutoff_date) as scraper:
    #     vulnerabilities = await scraper.scrape_vulnerabilities()
    #     scraper.save_vulnerabilities()
    #     processed_vulns = process_vulnerability_attributes(vulnerabilities)
    #     # save_processed_vulnerabilities(processed_vulns)
    #     # print("\nFound Vulnerabilities:")
    #     # print("=====================\n")
    #     # for vuln in processed_vulns:
    #     #     display_vulnerability(vuln)
    #     # print(f"\nTotal vulnerabilities found: {len(processed_vulns)}")


if __name__ == "__main__":
    asyncio.run(main())