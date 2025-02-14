# VulnShield - Automated CVE Monitoring API

**VulnShield** is a powerful **Flask-based RESTful API** designed to help enterprises **monitor vulnerabilities (CVEs) in real-time** and proactively secure their infrastructure.

With the increasing number of **cyber threats, exploits, and zero-day vulnerabilities**, organizations must stay updated to prevent attacks. **VulnShield** automates this process by **scraping security databases every 12 hours**, classifying vulnerabilities, and sending alerts via email.

## 🚀 Why VulnShield Matters

- **Cybersecurity threats evolve daily**, and unpatched vulnerabilities can lead to severe data breaches.  
- **Enterprises need a centralized system** to track vulnerabilities relevant to their software stack.  
- **Proactive security measures** (like automated CVE monitoring) are crucial for preventing **data leaks, malware infections, and ransomware attacks**.  
- **VulnShield ensures** that security teams stay informed without manual CVE hunting.  

---

## 🛠️ Setup & Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/VulnShield.git
cd VulnShield
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Configure Environment Variables

Create a `.env.production` file and set up the needed variables.


### 4️⃣ Run the API Server

```bash
python app.py
```

---

## 📌 Features

✅ **Automated Web Scraping** – Fetches new CVEs from multiple sources every **12 hours**.  
✅ **Classification & Filtering** – Organizes vulnerabilities based on severity, impact, and exploitability.  
✅ **Email Notifications** – Sends alerts using a **newsletter system (SMTP via ProtonMail)**.  
✅ **RESTful API** – Allows enterprises to query vulnerabilities via HTTP requests.  
✅ **Secure & Scalable** – Built with Flask and PostgreSQL for enterprise use.  

---

## 🚨 Important Notes

- This tool is **for educational and security research purposes only**.  
- **Ensure you comply with legal guidelines** when scraping third-party sources.  
- VulnShield is meant to **assist security teams, not replace** proper security practices.  

---

## 🤝 Contributing

Pull requests are welcome! Feel free to open an issue if you find a bug or want to suggest improvements.

---

## Contributing

Contributions are welcome! If you would like to improve Didy, feel free to submit a pull request.


## Authors

Developed by Belhanafi Abdelmadjid.

---

**🔒 Stay Secure!**
