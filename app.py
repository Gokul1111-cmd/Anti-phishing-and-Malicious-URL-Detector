from flask import Flask, request, render_template, redirect, url_for, jsonify
import csv
import os
from datetime import datetime
import pickle
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# Load trained model and vectorizer
with open('model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('vectorizer.pkl', 'rb') as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)

# Sample blacklist of known phishing URLs
phishing_blacklist = [
    "phishing-site.com",
    "fakebank.com",
    "malicious-site.org"
]

# File paths
urls_file = 'urls.csv'
quarantine_file = 'quarantine.csv'
settings_file = 'settings.csv'

def add_to_quarantine(url, date):
    with open(quarantine_file, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([url, date])

def get_quarantined_items():
    if not os.path.exists(quarantine_file):
        return []
    with open(quarantine_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        return list(reader)

def remove_from_quarantine(index):
    items = get_quarantined_items()
    if 0 <= index < len(items):
        items.pop(index)
        with open(quarantine_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(items)

def save_settings(background_analysis, malware_detection, optimization):
    with open(settings_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([background_analysis, malware_detection, optimization])

def get_settings():
    if not os.path.exists(settings_file):
        return {'background_analysis': 50, 'malware_detection': 75, 'optimization': 40}
    with open(settings_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        settings = next(reader)
        return {
            'background_analysis': int(settings[0]),
            'malware_detection': int(settings[1]),
            'optimization': int(settings[2])
        }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/malware')
def malware():
    last_scan = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    threats_found = len(get_quarantined_items())
    return render_template('malware.html', last_scan=last_scan, threats_found=threats_found)

@app.route('/redirect', methods=['POST'])
def redirect_to_detection():
    detection_type = request.form['detection_type']
    return redirect(url_for('home', detection_type=detection_type))

@app.route('/detect', methods=['POST'])
def detect():
    url = request.form['url']
    detection_type = request.form['detection_type']
    
    # Placeholder for actual detection logic
    if detection_type == 'antiphishing':
        result = 'Phishing' if any(phishing_site in url for phishing_site in phishing_blacklist) else 'Safe'
        if result == 'Phishing':
            add_to_quarantine(url, datetime.now().strftime('%Y-%m-%d'))
    elif detection_type == 'malware':
        result = 'Malware' if 'malware' in url else 'Safe'
        if result == 'Malware':
            add_to_quarantine(url, datetime.now().strftime('%Y-%m-%d'))
    else:
        result = 'Safe'
    
    return render_template('result.html', url=url, result=result)

@app.route('/protect')
def protect():
    return render_template('protect.html')

@app.route('/check_phishing', methods=['POST'])
def check_phishing():
    url = request.form['url']
    
    # Check against blacklist
    if any(phishing_site in url for phishing_site in phishing_blacklist):
        result = 'Phishing'
    else:
        # Use the trained model for prediction
        url_vectorized = vectorizer.transform([url])
        prediction = model.predict(url_vectorized)
        result = 'Phishing' if prediction == 'phishing' else 'Safe'
    
    return render_template('protect.html', url=url, result=result)

@app.route('/check_malware', methods=['POST'])
def check_malware():
    url = request.form['url']
    
    # Placeholder for actual malware detection logic
    result = 'Malware' if 'malware' in url else 'Safe'
    
    if result == 'Malware':
        add_to_quarantine(url, datetime.now().strftime('%Y-%m-%d'))
    
    last_scan = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    threats_found = len(get_quarantined_items())
    
    return render_template('malware.html', url=url, result=result, last_scan=last_scan, threats_found=threats_found)

@app.route('/quarantine')
def quarantine():
    items = get_quarantined_items()
    return render_template('quarantine.html', items=items)

@app.route('/settings')
def settings():
    settings = get_settings()
    return render_template('settings.html', settings=settings)

@app.route('/update_settings', methods=['POST'])
def update_settings():
    background_analysis = request.form.get('background_analysis', 50)
    malware_detection = request.form.get('malware_detection', 75)
    optimization = request.form.get('optimization', 40)
    
    save_settings(background_analysis, malware_detection, optimization)
    
    return redirect(url_for('settings'))

@app.route('/add_to_quarantine', methods=['POST'])
def add_to_quarantine_route():
    url = request.form['url']
    add_to_quarantine(url, datetime.now().strftime('%Y-%m-%d'))
    return redirect(url_for('protect'))

@app.route('/restore/<int:item_id>', methods=['POST'])
def restore(item_id):
    remove_from_quarantine(item_id)
    return redirect(url_for('quarantine'))

@app.route('/delete/<int:item_id>', methods=['POST'])
def delete(item_id):
    remove_from_quarantine(item_id)
    return redirect(url_for('quarantine'))

@app.route('/get_quarantine_data')
def get_quarantine_data():
    date = request.args.get('date')
    date_formatted = datetime.strptime(date, '%d %b').strftime('%Y-%m-%d')  # Adjust format as needed
    urls = []
    if os.path.exists(quarantine_file):
        with open(quarantine_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if row[1] == date_formatted:
                    urls.append(row[0])
    return jsonify({'urls': urls})

if __name__:
    app.run(debug=True)