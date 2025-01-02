from app.models import Vulnerability
from app import db
from app import create_app








# ---------------------------------------------------------------------------- #
#                                    Rayane                                    #
# ---------------------------------------------------------------------------- #

import spacy
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import re
import string

# Charger le modèle spaCy en anglais
nlp = spacy.load("en_core_web_sm")

# Charger les stopwords NLTK
stop_words = set(stopwords.words("english"))

# Liste des types d'attaques, chaque dictionnaire dispose d'un tableau de mots-clés
attack_types = [
    {"type": "Cross-Site Scripting (XSS)", 
     "keywords": ["xss", "cross site scripting", "cross-site scripting"]},

    {"type": "SQL Injection", 
     "keywords": ["sql injection", "sqli", "sql code injection"]},

    {"type": "Denial of Service (DoS)", 
     "keywords": ["denial of service", "denial-of-service", "dos", "service disruption"]},

    {"type": "Distributed Denial of Service (DDoS)", 
     "keywords": ["ddos", "distributed denial of service", "distributed dos"]},

    {"type": "Buffer Overflow", 
     "keywords": ["buffer overflow", "stack overflow", "heap overflow", "overflow"]},

    {"type": "Remote Code Execution (RCE)", 
     "keywords": ["rce", "remote code execution", "arbitrary code execution"]},

    {"type": "Privilege Escalation", 
     "keywords": ["privilege escalation", "escalation of privilege", "root access"]},

    {"type": "Directory Traversal", 
     "keywords": ["directory traversal", "path traversal", "../", "..\\"]},

    {"type": "Cross-Site Request Forgery (CSRF)", 
     "keywords": ["csrf", "cross site request forgery", "cross-site request forgery"]},

    {"type": "Code Injection", 
     "keywords": ["code injection", "arbitrary code injection", "script injection"]},

    {"type": "Information Disclosure", 
     "keywords": ["information disclosure", "data leakage", "sensitive data exposure"]},

    {"type": "Backdoor", 
     "keywords": ["backdoor", "hidden access", "unauthorized access"]},

    {"type": "Malware", 
     "keywords": ["malware", "virus", "trojan", "ransomware", "spyware", "adware", "worm"]},

    {"type": "Time-Of-Check Time-Of-Use (TOCTOU)", 
     "keywords": ["toctou", "time-of-check time-of-use", "time of check time of use", "race condition"]},

    {"type": "Man-in-the-Middle (MITM)", 
     "keywords": ["mitm", "man in the middle", "man-in-the-middle attack"]},

    {"type": "Phishing", 
     "keywords": ["phishing", "credential theft", "email scam"]},

    {"type": "Social Engineering", 
     "keywords": ["social engineering", "human manipulation", "deceptive attack"]},

    {"type": "Brute Force", 
     "keywords": ["brute force", "password cracking", "credential stuffing"]},

    {"type": "Zero-Day Exploit", 
     "keywords": ["zero-day", "zero day exploit", "0-day"]},

    {"type": "Insider Threat", 
     "keywords": ["insider threat", "internal attack", "employee attack"]},

    {"type": "Cryptojacking", 
     "keywords": ["cryptojacking", "crypto mining malware", "unauthorized mining"]},

    {"type": "Session Hijacking", 
     "keywords": ["session hijacking", "cookie theft", "token theft"]},

    {"type": "DNS Spoofing", 
     "keywords": ["dns spoofing", "dns cache poisoning", "fake dns"]},

    {"type": "ARP Spoofing", 
     "keywords": ["arp spoofing", "arp cache poisoning", "network spoofing"]},

    {"type": "Credential Dumping", 
     "keywords": ["credential dumping", "password extraction", "hash dumping"]},

    {"type": "Ransomware", 
     "keywords": ["ransomware", "file encryption attack", "data ransom"]},

    {"type": "Supply Chain Attack", 
     "keywords": ["supply chain attack", "third-party compromise", "dependency hijacking"]},

    {"type": "Clickjacking", 
     "keywords": ["clickjacking", "ui redress attack", "invisible overlay"]},

    {"type": "Side-Channel Attack", 
     "keywords": ["side-channel attack", "timing attack", "power analysis", "acoustic cryptanalysis"]},

    {"type": "Eavesdropping", 
     "keywords": ["eavesdropping", "packet sniffing", "interception"]},

    {"type": "Data Breach", 
     "keywords": ["data breach", "unauthorized data access", "information compromise"]},

    {"type": "XML External Entity (XXE)", 
     "keywords": ["xxe", "xml external entity", "xml attack"]},

    {"type": "Command Injection", 
     "keywords": ["command injection", "os command injection", "shell injection"]},

    {"type": "Domain Hijacking", 
     "keywords": ["domain hijacking", "dns takeover", "domain takeover"]},

    {"type": "Insufficient Authentication", 
     "keywords": ["insufficient authentication", "weak authentication", "authentication bypass"]},

    {"type": "Insufficient Authorization", 
     "keywords": ["insufficient authorization", "weak authorization", "privilege misuse"]}
]


# Liste des plateformes reconnues
platform_keywords = [
    # Operating Systems
    "windows", "linux", "macos", "ios", "android", "ubuntu", "centos", "debian", "redhat",
    "fedora", "kali linux", "opensuse", "manjaro", "gentoo", "arch linux", "alpine linux", 
    "raspbian", "pop!_os", "zorin os", "elementary os", "rocky linux", "amazon linux",
    "solaris", "freebsd", "netbsd", "openbsd", "dragonfly bsd", "chrome os", "haiku os",
    "tails", "whonix", "endless os",

    # Cloud Providers
    "aws", "azure", "gcp", "oracle cloud", "ibm cloud", "digitalocean", "linode",
    "heroku", "vultr", "openstack", "cloudflare", "akamai", "ovhcloud", "scaleway", 
    "rackspace",

    # Virtualization and Containerization
    "docker", "kubernetes", "vmware", "virtualbox", "hyper-v", "proxmox", "xen", "qemu", 
    "vagrant", "parallels", "openvz", "rkt", "cri-o", "lxc", "libvirt",

    # Web Servers and Technologies
    "apache", "nginx", "iis", "lighttpd", "caddy", "tomcat", "jetty", "gunicorn", 
    "uwsgi", "node.js", "express.js", "django", "flask", "ruby on rails", "laravel",
    "spring boot",

    # Databases
    "mysql", "postgresql", "sqlite", "oracle database", "microsoft sql server", "mongodb",
    "redis", "elasticsearch", "cassandra", "hbase", "dynamodb", "couchdb", "firebase",
    "neo4j", "arangodb", "clickhouse", "influxdb", "timescaledb", "snowflake",

    # Networking and Security
    "cisco", "juniper", "palo alto", "checkpoint", "fortinet", "mikrotik", "opnsense",
    "pfSense", "sonicwall", "watchguard", "aruba", "huawei", "ubiquiti", "netgear",
    "tp-link", "linksys", "vyos", "meraki",

    # Development Platforms
    "github", "gitlab", "bitbucket", "sourceforge", "gitea", "azure devops", "jenkins",
    "travis ci", "circleci", "teamcity", "bamboo", "sonarqube", "katalon", "postman",

    # Browsers
    "firefox", "chrome", "safari", "edge", "opera", "vivaldi", "brave", "tor browser",

    # Mobile Platforms
    "tvos", "watchos", "ipados", "android wear", "visionos", "fire os", "kaios",
    "sailfish os", "blackberry os", "symbian", "bada os", "tizen",

    # Gaming and Entertainment
    "playstation", "xbox", "nintendo", "steam", "epic games", "gog", "origin", "battle.net",
    "uplay", "roblox", "unity", "unreal engine", "godot engine", "cryengine",

    # Big Data and Analytics
    "hadoop", "spark", "cloudera", "databricks", "kafka", "elastic stack", "splunk",
    "tableau", "power bi", "qlik", "looker", "sas", "snowflake", "informatica",

    # DevOps and CI/CD Tools
    "ansible", "terraform", "chef", "puppet", "saltstack", "spinnaker", "argo", 
    "rundeck", "consul", "vault", "nomad",

    # Hardware Vendors
    "lenovo", "dell", "hp", "asus", "acer", "samsung", "huawei", "xiaomi", 
    "microsoft surface", "apple", "razer", "msi",

    # Social Media and Communication
    "facebook", "twitter", "instagram", "linkedin", "snapchat", "tiktok", "discord",
    "slack", "zoom", "microsoft teams", "webex", "skype", "whatsapp", "telegram",
    "signal",

    # Blockchain and Cryptography
    "bitcoin", "ethereum", "solana", "cardano", "polkadot", "avalanche", "stellar",
    "ripple", "hyperledger", "celo", "chainlink", "arbitrum", "cosmos",

    # Miscellaneous Platforms
    "wordpress.org", "joomla", "drupal", "shopify", "magento", "prestashop",
    "squarespace", "wix", "weebly", "ghost", "medium", "notion", "airtable",
    "trello", "asana", "monday.com", "jira", "confluence", "miro",

    # AI/ML Platforms
    "tensorflow", "pytorch", "keras", "scikit-learn", "h2o.ai", "datarobot", 
    "vertex ai", "sagemaker", "hugging face", "rapidminer", "caffe", "mlflow",
    "weka", "knime"
]


software_keywords = [
    # Web Servers and Middleware
    "apache", "nginx", "iis", "caddy", "tomcat", "wildfly", "jboss", "glassfish",
    "lighttpd", "haproxy", "varnish",

    # Databases
    "mysql", "postgresql", "mongodb", "redis", "sqlite", "mariadb", "oracle database", 
    "db2", "mssql", "cassandra", "couchdb", "dynamodb", "firebase", "arangodb",
    "clickhouse", "influxdb", "timescaledb", "snowflake", "neo4j", "hbase",

    # Programming Languages and Runtimes
    "php", "python", "perl", "ruby", "node.js", "java", "go", "rust", "c", "c++", "c#",
    ".net", "swift", "kotlin", "typescript", "javascript", "scala", "elixir", 
    "dart", "haskell", "r", "matlab", "fortran", "cobol",

    # CMS and E-commerce
    "wordpress", "joomla", "drupal", "magento", "shopify", "woocommerce", 
    "prestashop", "typo3", "ghost", "bigcommerce", "squarespace", "wix", "weebly",

    # DevOps and Automation Tools
    "jenkins", "gitlab", "github", "bitbucket", "travis-ci", "circleci", "azure pipelines",
    "ansible", "puppet", "chef", "saltstack", "terraform", "packer", "vagrant", "rundeck",
    "teamcity", "bamboo", "argo", "spinnaker", "helm", "kustomize", "consul", "vault", "nomad",

    # Monitoring and Logging
    "logstash", "elasticsearch", "kibana", "grafana", "prometheus", "splunk", 
    "syslog-ng", "fluentd", "zabbix", "nagios", "new relic", "datadog", 
    "dynatrace", "solarwinds", "uptime robot", "pingdom",

    # Networking and Security Tools
    "wireshark", "metasploit", "burpsuite", "nessus", "nmap", "aircrack-ng", 
    "ettercap", "john the ripper", "hashcat", "sqlmap", "openvas", "cobalt strike",
    "snort", "suricata", "ossec", "clamav", "kali linux tools",

    # Collaboration and Communication
    "teams", "slack", "zoom", "skype", "webex", "discord", "google meet", 
    "microsoft outlook", "thunderbird", "mailchimp", "hubspot", "salesforce",

    # Design and Multimedia
    "adobe acrobat", "photoshop", "illustrator", "premiere pro", "after effects",
    "autodesk maya", "autodesk 3ds max", "blender", "gimp", "inkscape", 
    "davinci resolve", "final cut pro", "audacity", "logic pro", "garageband",

    # Analytics and Data Science
    "tableau", "power bi", "qlik sense", "lookml", "sas", "stata", "h2o.ai", 
    "rapidminer", "knime", "mlflow", "tensorflow", "pytorch", "scikit-learn", 
    "keras", "matplotlib", "seaborn", "pandas", "numpy",

    # Virtualization and Containers
    "docker", "kubernetes", "vmware", "virtualbox", "hyper-v", "qemu", 
    "proxmox", "parallels desktop", "openvz", "xenserver", "podman", "lxc",

    # AI/ML and Automation Tools
    "tensorflow", "pytorch", "keras", "openai", "hugging face", "rapidminer", 
    "caffe", "spacy", "nltk", "weka", "vertex ai", "sagemaker", "h2o.ai",

    # Productivity and Office Tools
    "microsoft office", "google workspace", "libreoffice", "onlyoffice",
    "notion", "trello", "asana", "monday.com", "todoist", "obsidian",
    "evernote", "confluence", "miro",

    # Browsers
    "google chrome", "mozilla firefox", "microsoft edge", "apple safari",
    "opera", "vivaldi", "brave", "tor browser",

    # Backup and Recovery Tools
    "veeam", "acronis", "bacula", "backup exec", "duplicity", "rsync", 
    "crashplan", "carbonite", "time machine", "rclone",

    # Game Engines and Development Tools
    "unity", "unreal engine", "godot", "cryengine", "rpg maker", 
    "game maker studio", "construct 3", "twine", "ren'py",

    # Miscellaneous
    "openssh", "openssl", "ngrok", "wireshark", "powershell", "bash",
    "zsh", "fish", "tmux", "screen", "putty", "filezilla", "winscp"
]

# Fonction pour extraire des mots-clés à partir de la description
def extract_keywords(description):
    """Extrait les mots-clés d'une description en utilisant NLTK et spaCy."""
    # Tokenisation avec NLTK
    tokens = word_tokenize(description)
    tokens = [word.lower() for word in tokens if word.isalnum()]  # Garder uniquement les alphanumériques
    tokens = [word for word in tokens if word not in stop_words]  # Supprimer les stopwords

    # Analyse avec spaCy pour identifier les entités
    doc = nlp(description)
    entities = [ent.text.lower() for ent in doc.ents]

    # Combinaison des tokens filtrés et des entités
    keywords = set(tokens + entities)
    return keywords

# Fonction pour détecter le type d'attaque
def detect_attack_type(keywords, description):
    normalized_description = description.lower()
    for attack in attack_types:
        for keyword in attack["keywords"]:
            if keyword in keywords or re.search(rf"\\b{re.escape(keyword)}\\b", normalized_description):
                return attack["type"]
    return "Unknown"

# Fonction pour détecter les plateformes affectées
def detect_platforms(keywords, description):
    normalized_description = description.lower()
    platforms_found = [
        platform for platform in platform_keywords
        if platform in keywords or re.search(rf"\\b{re.escape(platform)}\\b", normalized_description)
    ]

    return ", ".join(set(platforms_found)) if platforms_found else "Unknown"

# Fonction pour filtrer les tags non pertinents
def filter_tags(keywords):
    # Exclure les mots de moins de 3 caractères ou communs
    irrelevant_words = {"the", "and", "with", "for", "from", "able", "improved", "input"}
    filtered = [word for word in keywords if len(word) > 2 and word not in irrelevant_words]
    return ", ".join(set(filtered))

# Fonction pour remplir les attributs manquants
# Fonction pour détecter les logiciels affectés
def detect_software(keywords, description):
    normalized_description = description.lower()
    software_found = [
        software for software in software_keywords
        if software in keywords or re.search(rf"\\b{re.escape(software)}\\b", normalized_description)
    ]
    return ", ".join(set(software_found)) if software_found else "Unknown"


# Fonction pour remplir les attributs manquants avec séparation des plateformes
def fill_missing_attributes(cve_data):
    """Remplit les attributs manquants en utilisant les mots-clés extraits de la description."""
    description = cve_data.get("Description", "")
    keywords = extract_keywords(description)

    # Type d'attaque
    cve_data["Type"] = detect_attack_type(keywords, description)

    # Plateformes affectées
    cve_data["Platform"] = detect_platforms(keywords, description)

    # Logiciels affectés
    cve_data["Affected_Software"] = detect_software(keywords, description)

    # Tags enrichis et filtrés
    cve_data["Tags"] = filter_tags(keywords)

    return cve_data


# cve_example = {  
# "CVE_ID": "CVE-2024-12694",
#     "Title": "Google Chrome Vulnerability: CVE-2024-12694 Use after free in Compositing",
#     "Description": "Use after free in Compositing in Google Chrome prior to 131.0.6778.204 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High) Use after free in Compositing in Google Chrome prior to 131.0.6778.204 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)",
#     "Date_Published": "12/19/2024",
#     "Created": "12/20/2024",
#     "Added": "12/19/2024",
#     "Last_Modified": "12/20/2024",
#     "Type": "N/A",
#     "Platform": "N/A",
#     "Author": "Rapid7",
#     "Severity": "4",
#     "CVSS": "(AV:L/AC:M/Au:N/C:P/I:P/A:P)",
#     "Solutions": [
#       "google-chrome-upgrade-latest"
#     ],
#     "References": [
#       "https://attackerkb.com/topics/cve-2024-12694",
#       "https://cve.mitre.org/cgi-bin/cvename.cgi?name=2024-12694"
#     ],
#     "Base_Score": "N/A",
#     "Attack_Vector": "N/A",
#     "Attack_Complexity": "N/A",
#     "Privileges_Required": "N/A",
#     "User_Interaction": "N/A",
#     "Scope": "N/A",
#     "Exploitability_Score": "N/A",
#     "Impact_Score": "N/A",
#     "Confidentiality_Impact": "N/A",
#     "Integrity_Impact": "N/A",
#     "Availability_Impact": "N/A",
#     "Affected_Software": [],
#     "verified": "false",
#     "tags": []
# }

# # Remplir les attributs manquants
# filled_cve = fill_missing_attributes(cve_example)

# # Afficher le résultat
# print("==============================")
# for key, value in filled_cve.items():
#     print(f"{key}: {value}")


# ---------------------------------------------------------------------------- #
#                                    Rayane                                    #
# ---------------------------------------------------------------------------- #



def process_cve(cve):
    # Exemple de traitement de texte pour modifier les attributs de la CVE
    # Vous pouvez ajouter votre logique de traitement de texte ici
    # cve['Titre'] = cve['Titre'].upper()  # Exemple de modification
    # cve['Description'] = cve['Description'].capitalize()  # Exemple de modification
    # Ajoutez d'autres modifications selon vos besoins
    return fill_missing_attributes(cve)

def process_all_cves(cves):
    
    for cve in cves:
        processed_cve = process_cve(cve.to_dict())
        existing_vuln = Vulnerability.query.filter_by(cve_id=processed_cve['CVE_ID']).first()
        if existing_vuln:
            # Mettre à jour les champs de la CVE existante
            for key, value in processed_cve.items():
                # if value is not None:
                if key == "Tags":
                    val = value
                    if len(val) > 254:
                        val = val[:254]  # Truncate the string to 1024 characters
                    setattr(existing_vuln, key.lower(), val)
                else :
                    setattr(existing_vuln, key.lower(), value)
            existing_vuln.status = 'encours-traitement'
            db.session.commit()







# Example usage for testing
if __name__ == "__main__":
    with create_app().app_context():
        scraped_vulnerabilities = [
            
        ]
        scraped_vulnerabilities.append(Vulnerability.query.filter_by(cve_id="CVE-2024-51973").first().to_dict())
        # Call the function to process and update vulnerabilities
        process_all_cves(scraped_vulnerabilities)