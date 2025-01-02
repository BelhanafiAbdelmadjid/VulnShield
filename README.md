# VTBDD
VTBDD uni project

git pull 
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000

git pull 
flask db migrate -m ""
flask db upgrade
export FLASK_ENV=production
flask run --host=0.0.0.0 --port=5000





# Init the DB with some CVEs 
python -m app.utils.Cve
the file will use ExploitDB only and get arround 318 CVEs from the last 12 months


# Dépendance traitement de text 
pip install spacy 
python3 -m spacy download en_core_web_sm

in cmd access python console : 
import nltk
nltk.download('stopwords')
nltk.download('punkt_tab')