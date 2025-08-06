# 🔒 Malicious URL Detection

A web app to detect whether a URL is malicious or benign using machine learning.

## 🧠 Description

This project uses a Logistic Regression model trained on a labeled dataset of URLs to classify new URLs as either **malicious** (phishing, malware, defacement) or **benign**. The app is built with **Streamlit** for real-time predictions.

## 🚀 Features

- Extracts 20+ URL-based features (e.g., IP usage, suspicious keywords, shortening services)
- Trained using logistic regression
- Streamlit-based interactive UI
- Classifies URLs as **Malicious** or **Benign**

## 🛠 Tech Stack

- Python  
- Pandas, NumPy  
- Scikit-learn  
- Streamlit  
- TLDExtract / URL parsing libraries

## ▶️ Run Locally

```bash
# Install dependencies
pip install pandas numpy scikit-learn streamlit tld

# Run the Streamlit app
streamlit run malicious_url_detection.py
