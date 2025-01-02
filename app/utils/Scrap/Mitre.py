import requests
import json
import os
# import pandas as pd
from bs4 import BeautifulSoup
from typing import Union, List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import sys


# hada oulach date
# donc dertlo time range but the only option that works is the last one 4. All CVEs cuz the year is existed in xml file
class CVEMitreDetailedScraper:
    def __init__(
        self,
        years: Optional[Union[str, List[str]]] = None,
        timeout: int = 30,
        batch_size: int = 1000,
        time_filter: Optional[Dict[str, Union[int, str]]] = None,
    ):
        self.years = self._process_years(years)
        self.timeout = timeout
        self.batch_size = batch_size
        self.current_date = datetime.now()
        self.time_filter = time_filter
        self.logger = self._setup_logging()
        self.session = self._setup_session()

    def _process_years(
        self, years: Optional[Union[str, List[str]]] = None
    ) -> List[str]:
        if years is None:
            return [str(datetime.now().year)]

        if isinstance(years, str):
            if "," in years:
                year_list = [y.strip() for y in years.split(",")]
            else:
                year_list = [years.strip()]
        elif isinstance(years, list):
            year_list = [str(y).strip() for y in years]
        else:
            raise ValueError("Years must be string or list")

        current_year = datetime.now().year
        for year in year_list:
            if not year.isdigit() or int(year) < 1999 or int(year) > current_year:
                raise ValueError(
                    f"Invalid year: {year}. Must be between 1999 and {current_year}"
                )

        return year_list

    def is_within_timeframe(
        self, date_str: str, time_value: int, time_unit: str
    ) -> bool:
        try:
            date = datetime.strptime(date_str, "%Y-%m-%d")
            time_delta = {
                "hours": timedelta(hours=time_value),
                "days": timedelta(days=time_value),
                "months": timedelta(days=time_value * 30),
            }.get(time_unit)
            if not time_delta:
                raise ValueError("Invalid time unit")
            return date >= self.current_date - time_delta
        except (ValueError, TypeError):
            return False

    def _setup_logging(self) -> logging.Logger:
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        return logging.getLogger(__name__)

    def _setup_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        return session

    def _create_cve_entry(self, vuln: BeautifulSoup) -> Optional[Dict[str, Any]]:
        def get_text_safe(
            element: BeautifulSoup,
            selector: Optional[str] = None,
            attrs: Optional[Dict] = None,
        ) -> Optional[str]:
            try:
                if selector:
                    found = element.find(selector, attrs or {})
                else:
                    found = element
                return found.text.strip() if found else "N/A"
            except (AttributeError, TypeError):
                return "N/A"

        date_published = get_text_safe(vuln, "date")

        if self.time_filter and date_published:
            if not self.is_within_timeframe(
                date_published, self.time_filter["value"], self.time_filter["unit"]
            ):
                return None

        return {
            "CVE_ID": get_text_safe(vuln, "title"),
            "Description": get_text_safe(vuln, "note", {"ordinal": "1"}),
            "Date_Published": date_published,
            "Severity": "N/A",
            "CVSS": "N/A",
            "References": [],
        }

    def scrape_cves(self) -> List[Dict[str, Any]]:
        all_cves_data = []
        base_url = "https://cve.mitre.org/data/downloads/allitems-cvrf-year-"

        for year in self.years:
            self.logger.info(f"Processing year {year}...")
            url = f"{base_url}{year}.xml"

            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()

                soup = BeautifulSoup(response.text, "lxml")
                vulnerabilities = soup.find_all("vulnerability")

                for i in range(0, len(vulnerabilities), self.batch_size):
                    batch = vulnerabilities[i : i + self.batch_size]
                    batch_data = []

                    for vuln in batch:
                        try:
                            cve_entry = self._create_cve_entry(vuln)
                            if cve_entry:
                                batch_data.append(cve_entry)
                        except Exception as e:
                            self.logger.warning(
                                f"Failed to parse vulnerability: {str(e)}"
                            )
                            continue

                    all_cves_data.extend(batch_data)
                    self.logger.info(
                        f"Processed {len(all_cves_data)} entries for {year}..."
                    )

            except requests.RequestException as e:
                self.logger.error(f"Failed to fetch data for year {year}: {str(e)}")
                continue

        print(json.dumps(all_cves_data, indent=2))
        return all_cves_data

    # def to_dataframe(self, cve_data: List[Dict[str, Any]]) -> pd.DataFrame:
    #     return pd.DataFrame(cve_data)


def get_user_choice() -> Tuple[Optional[int], Optional[str]]:
    print("\n=== MITRE CVE Scraper ===")
    print("1. Last few hours")
    print("2. Last few days")
    print("3. Last few months")
    print("4. All CVEs")
    print("5. Exit")

    while True:
        try:
            choice = int(input("\nEnter your choice (1-5): "))
            if choice == 5:
                return None, None
            if choice == 4:
                return 0, None

            units = {1: "hours", 2: "days", 3: "months"}
            if choice in units:
                value = int(input(f"Enter the number of {units[choice]}: "))
                if value > 0:
                    return value, units[choice]
            print("Please enter a valid choice and positive number.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def get_years() -> List[str]:
    while True:
        years = input(
            "\nEnter years to scrape (comma-separated, press Enter for current year): "
        ).strip()
        if not years:
            return [str(datetime.now().year)]
        try:
            year_list = [y.strip() for y in years.split(",")]
            current_year = datetime.now().year
            if all(y.isdigit() and 1999 <= int(y) <= current_year for y in year_list):
                return year_list
            print(f"Years must be between 1999 and {current_year}")
        except ValueError:
            print("Invalid input. Please enter valid years.")


def main():
    while True:
        time_value, time_unit = get_user_choice()
        if time_value is None and time_unit is None:
            print("\nExiting...")
            sys.exit(0)

        years = get_years()
        time_filter = (
            {"value": time_value, "unit": time_unit} if time_value != 0 else None
        )

        try:
            scraper = CVEMitreDetailedScraper(years=years, time_filter=time_filter)
            cve_data = scraper.scrape_cves()
            # df = scraper.to_dataframe(cve_data)

            print(f"\nSuccessfully scraped {len(cve_data)} CVEs")
            print(len(cve_data))
            # if len(df) > 0:
            #     print("\nSample of scraped CVEs:")
            #     print(df[["CVE_ID", "Date_Published", "Description"]].head())

        except Exception as e:
            print(f"\nError occurred: {str(e)}")

        if input("\nWould you like to perform another search? (y/n): ").lower() != "y":
            print("\nExiting...")
            break


if __name__ == "__main__":
    main()