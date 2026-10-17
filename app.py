from flask import Flask, render_template, request
import pickle
import re
import random

app = Flask(__name__)

vector = pickle.load(open("vectorizer.pkl", 'rb'))
model = pickle.load(open("phishing.pkl", 'rb'))



def get_explanation(url):
    reasons = []

    
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        reasons.append("Uses IP address instead of domain") 

   
    if url.count('-') > 2:
        reasons.append("Too many '-' symbols (common in fake domains)")

    
    suspicious_words = ['login', 'verify', 'update', 'secure', 'bank', 'free']
    for word in suspicious_words:
        if word in url.lower():
            reasons.append(f"Contains suspicious word: '{word}'")

   
    if not url.startswith("https"):
        reasons.append("Not using HTTPS (not secure)")

    
    if len(url) > 75:
        reasons.append("URL is unusually long")

    return reasons                       


@app.route("/", methods=['GET', 'POST'])
def index():

    if request.method == "POST":
        url = request.form['url']

        cleaned_url = re.sub(r'^https?://(www\.)?', '', url)

        predict = model.predict(vector.transform([cleaned_url]))[0]

        
        reasons = get_explanation(url)

        
        score = 0
        risk = "Low"
        message = ""

        if predict == 'bad':
            score = random.randint(70, 95)
            risk = "High"
            message = "⚠️ This is a Phishing website !!"

        elif predict == 'good':
            score = random.randint(5, 30)
            risk = "Low"
            message = "✅ This is a safe website"

        else:
            score = random.randint(40, 60)
            risk = "Medium"
            message = "⚠️ This website looks suspicious"

        return render_template(
            "index.html",
            predict=message,
            score=score,
            risk=risk,
            reasons=reasons   
        )

    else:
        return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)



