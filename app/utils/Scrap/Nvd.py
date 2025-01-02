import requests
import json
import csv
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv


# la memechose juste hada plus rapide 3la les autres means you can find the resule if yoy scrappe the data in hours
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


class EnhancedNVDVulnerabilityFetcher:
    def __init__(self):
        load_dotenv()
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            "Accept": "application/json",
            "apiKey": os.getenv("NVD_API_KEY"),
        }

    def _get_time_range(self, time_value, time_unit):
        end_date = datetime.now()
        if time_unit == "hours":
            start_date = end_date - timedelta(hours=time_value)
        elif time_unit == "days":
            start_date = end_date - timedelta(days=time_value)
        elif time_unit == "months":
            current_year = end_date.year
            current_month = end_date.month
            target_month = current_month - time_value + 1
            target_year = current_year
            while target_month <= 0:
                target_month += 12
                target_year -= 1
            start_date = datetime(target_year, target_month, 1)
        return start_date, end_date

    def _parse_cvss_metrics(self, metrics):
        if not metrics:
            return {
                "Base_Score": "N/A",
                "Attack_Vector": "N/A",
                "Attack_Complexity": "N/A",
                "Privileges_Required": "N/A",
                "User_Interaction": "N/A",
                "Scope": "N/A",
                "Exploitability_Score": "N/A",
                "Impact_Score": "N/A",
                "Confidentiality_Impact": "N/A",
                "Integrity_Impact": "N/A",
                "Availability_Impact": "N/A",
            }

        cvss_data = metrics[0].get("cvssData", {})
        return {
            "Base_Score": cvss_data.get("baseScore", "N/A"),
            "Attack_Vector": cvss_data.get("attackVector", "N/A"),
            "Attack_Complexity": cvss_data.get("attackComplexity", "N/A"),
            "Privileges_Required": cvss_data.get("privilegesRequired", "N/A"),
            "User_Interaction": cvss_data.get("userInteraction", "N/A"),
            "Scope": cvss_data.get("scope", "N/A"),
            "Exploitability_Score": metrics[0].get("exploitabilityScore", "N/A"),
            "Impact_Score": metrics[0].get("impactScore", "N/A"),
            "Confidentiality_Impact": cvss_data.get("confidentialityImpact", "N/A"),
            "Integrity_Impact": cvss_data.get("integrityImpact", "N/A"),
            "Availability_Impact": cvss_data.get("availabilityImpact", "N/A"),
        }

    def _get_references(self, refs):
        return [ref.get("url") for ref in refs] if refs else "N/A"

    def _get_affected_software(self, configurations):
        if not configurations:
            return "N/A"

        affected_software = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    affected_software.append(cpe_match.get("criteria"))
        return affected_software if affected_software else "N/A"

    def _get_description(self, cve):
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "No description available")
        return "No description available"

    def fetch_vulnerabilities(self, time_value, time_unit):
        start_date, end_date = self._get_time_range(time_value, time_unit)
        vulnerabilities = []

        print(
            f"\n[+] Fetching vulnerabilities from {start_date.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        print(f"[+] To {end_date.strftime('%Y-%m-%d %H:%M:%S')}")

        params = {
            "resultsPerPage": 2000,
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }

        try:
            response = requests.get(self.base_url, headers=self.headers, params=params)
            response.raise_for_status()
            data = response.json()

            for cve in data.get("vulnerabilities", []):
                vuln_data = cve.get("cve", {})
                metrics = vuln_data.get("metrics", {}).get("cvssMetrics", [])
                cvss_metrics = self._parse_cvss_metrics(metrics)
                references = self._get_references(vuln_data.get("references", []))
                affected_software = self._get_affected_software(
                    vuln_data.get("configurations", [])
                )

                vulnerability = {
                    "CVE_ID": vuln_data.get("id", "N/A"),
                    "Titre": vuln_data.get("title", "N/A"),
                    "Description": self._get_description(vuln_data),
                    "Date_Published": vuln_data.get("published", "N/A"),
                    "Last_Modified": vuln_data.get("lastModified", "N/A"),
                    "Type": "N/A",
                    "Platform": "N/A",
                    "Author": "N/A",
                    "Severity": vuln_data.get("metrics", {}).get("severity", "N/A"),
                    "References": references,
                    "CVSS": cvss_metrics.get("Base_Score", "N/A"),
                    "Created": "N/A",
                    "Added": "N/A",
                    "Solutions": "N/A",
                    "verified": None,
                    "application_path": "N/A",
                    "application_md5": "N/A",
                    "Base_Score": cvss_metrics.get("Base_Score", "N/A"),
                    "Attack_Vector": cvss_metrics.get("Attack_Vector", "N/A"),
                    "Attack_Complexity": cvss_metrics.get("Attack_Complexity", "N/A"),
                    "Privileges_Required": cvss_metrics.get(
                        "Privileges_Required", "N/A"
                    ),
                    "User_Interaction": cvss_metrics.get("User_Interaction", "N/A"),
                    "Scope": cvss_metrics.get("Scope", "N/A"),
                    "Exploitability_Score": cvss_metrics.get(
                        "Exploitability_Score", "N/A"
                    ),
                    "Impact_Score": cvss_metrics.get("Impact_Score", "N/A"),
                    "Confidentiality_Impact": cvss_metrics.get(
                        "Confidentiality_Impact", "N/A"
                    ),
                    "Integrity_Impact": cvss_metrics.get("Integrity_Impact", "N/A"),
                    "Availability_Impact": cvss_metrics.get(
                        "Availability_Impact", "N/A"
                    ),
                    "Affected_Software": affected_software,
                    "tags": "N/A",
                    "screenshot_path": "N/A",
                    "screenshot_thumb_path": "N/A",
                }
                vulnerabilities.append(vulnerability)
                print(json.dumps(vulnerability, indent=4))
                print()

        except requests.RequestException as e:
            print(f"[!] Error fetching data: {str(e)}")
            return []

        return vulnerabilities

    def save_to_csv(self, vulnerabilities, time_value, time_unit):
        """
        Save vulnerabilities to a CSV file.
        This method is currently commented out as requested.

        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            time_value (int): Time value for filename
            time_unit (str): Time unit for filename

        Returns:
            str: Filename of saved CSV file or None if no vulnerabilities
        """
        # if not vulnerabilities:
        #     return None

        # filename = f"nvd_vulns_last_{time_value}_{time_unit}_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
        # with open(filename, "w", newline="", encoding="utf-8") as f:
        #     fieldnames = list(vulnerabilities[0].keys())
        #     writer = csv.DictWriter(f, fieldnames=fieldnames)
        #     writer.writeheader()
        #     writer.writerows(vulnerabilities)
        # return filename
        pass

    def save_to_json(self, vulnerabilities, time_value, time_unit):
        """
        Save vulnerabilities to a JSON file.
        This method is currently commented out as requested.

        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            time_value (int): Time value for filename
            time_unit (str): Time unit for filename

        Returns:
            str: Filename of saved JSON file or None if no vulnerabilities
        """
        # if not vulnerabilities:
        #     return None

        # filename = f"nvd_vulns_last_{time_value}_{time_unit}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        # with open(filename, "w", encoding="utf-8") as f:
        #     json.dump(vulnerabilities, f, indent=4)
        # return filename
        pass


def main():
    fetcher = EnhancedNVDVulnerabilityFetcher()

    # while True:
    #     print("\n=== Enhanced NVD Vulnerability Fetcher ===")
    #     print("Choose time range to fetch CVEs:")
    #     print("1. Last X hours")
    #     print("2. Last X days")
    #     print("3. Last X months")
    #     print("4. Exit")

    #     try:
    #         choice = input("\nEnter your choice (1-4): ").strip()

    #         if choice == "4":
    #             print("\nExiting program. Goodbye!")
    #             break

    #         if choice not in ["1", "2", "3"]:
    #             print("[!] Invalid choice. Please enter a number between 1 and 4.")
    #             continue

    #         time_unit = {"1": "hours", "2": "days", "3": "months"}[choice]
    #         time_value = int(input(f"Enter number of {time_unit}: "))

    #         if time_value <= 0:
    #             print("[!] Please enter a positive number.")
    #             continue

    #         print(f"\n[+] Fetching CVEs for the last {time_value} {time_unit}")
    #         vulnerabilities = fetcher.fetch_vulnerabilities(time_value, time_unit)

    #         if vulnerabilities:
    #             # csv_file = fetcher.save_to_csv(vulnerabilities, time_value, time_unit)  # Commented out CSV generation
    #             # json_file = fetcher.save_to_json(vulnerabilities, time_value, time_unit)  # Commented out JSON generation
    #             print(f"\n[+] Files saved:")
    #             # print(f"[+] CSV file: {csv_file}")  # Commented out CSV file message
    #             # print(f"[+] JSON file: {json_file}")  # Commented out JSON file message
    #             print(f"\nTotal vulnerabilities found: {len(vulnerabilities)}")
    #         else:
    #             print("\n[!] No vulnerabilities found for the specified time range")

    #     except ValueError:
    #         print("[!] Please enter a valid number.")
    #         continue

    #     choice = input("\nWould you like to fetch another time range? (y/n): ").lower()
    #     if choice != "y":
    #         print("\nExiting program. Goodbye!")
    #         break

    vulnerabilities = fetcher.fetch_vulnerabilities(12, "hours")
    print(len(vulnerabilities))

if __name__ == "__main__":
    main()