import streamlit as st
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from urllib.parse import urlparse
import re
from tld import get_tld


data = pd.read_csv("C:\\Users\\vasan\\Projects V\\Malicious url detection\\malicious_phish.csv")

mapping = {'benign': 'good', 'defacement': 'bad', 'phishing': 'bad', 'malware': 'bad'}
data['type'] = data['type'].replace(mapping)

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def count_www(url):
    return url.count('www')

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_dot(url):
    return url.count('.')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search('bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|cli\\.gs|'
                      'yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|twurl\\.nl|snipurl\\.com|'
                      'short\\.to|BudURL\\.com|ping\\.fm|post\\.ly|Just\\.as|bkite\\.com|snipr\\.com|fic\\.kr|loopt\\.us|'
                      'doiop\\.com|short\\.ie|kl\\.am|wp\\.me|rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|t\\.co|lnkd\\.in|'
                      'db\\.tt|qr\\.ae|adataset\\.ly|goo\\.gl|bitly\\.com|cur\\.lv|tinyurl\\.com|ow\\.ly|bit\\.ly|ity\\.im|'
                      'q\\.gs|is\\.gd|po\\.st|bc\\.vc|twitthis\\.com|u\\.to|j\\.mp|buzurl\\.com|cutt\\.us|u\\.bb|yourls\\.org|'
                      'x\\.co|prettylinkpro\\.com|scrnch\\.me|filoops\\.info|vzturl\\.com|qr\\.net|1url\\.com|tweez\\.me|v\\.gd|'
                      'tr\\.im|link\\.zip\\.net', url)
    return 1 if match else 0

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
    return 1 if match else 0

def digit_count(url):
    return sum(i.isnumeric() for i in url)

def letter_count(url):
    return sum(i.isalpha() for i in url)

def abnormal_url(url):
    hostname = urlparse(url).hostname
    return 0 if hostname and hostname in url else 1

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' 
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url) 
    return 1 if match else 0

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

data['url_length'] = data['url'].apply(url_length)
data['hostname_length'] = data['url'].apply(hostname_length)
data['count-www'] = data['url'].apply(count_www)
data['count-https'] = data['url'].apply(count_https)
data['count-http'] = data['url'].apply(count_http)
data['count.'] = data['url'].apply(count_dot)
data['count%'] = data['url'].apply(count_per)
data['count?'] = data['url'].apply(count_ques)
data['count-'] = data['url'].apply(count_hyphen)
data['count='] = data['url'].apply(count_equal)
data['count@'] = data['url'].apply(count_atrate)
data['count_dir'] = data['url'].apply(no_of_dir)
data['count_embed_domian'] = data['url'].apply(no_of_embed)
data['short_url'] = data['url'].apply(shortening_service)
data['fd_length'] = data['url'].apply(fd_length)
data['tld'] = data['url'].apply(lambda i: get_tld(i, fail_silently=True))
data['tld_length'] = data['tld'].apply(tld_length)
data['sus_url'] = data['url'].apply(suspicious_words)
data['count-digits'] = data['url'].apply(digit_count)
data['count-letters'] = data['url'].apply(letter_count)
data['abnormal_url'] = data['url'].apply(abnormal_url)
data['use_of_ip_address'] = data['url'].apply(having_ip_address)


data.dropna(inplace=True)


lb_make = LabelEncoder()
data['class_type'] = lb_make.fit_transform(data['type'])

X = data[['use_of_ip_address', 'abnormal_url', 'count-www', 'count@', 'count_dir', 'count_embed_domian', 'short_url', 'count-https', 'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length', 'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits', 'count-letters']]
y = data['class_type']


x_train, x_test, Y_train, Y_test = train_test_split(X, y, test_size=0.2, random_state=42)


classifier = LogisticRegression(max_iter=2000, random_state=42)
classifier.fit(x_train, Y_train)

st.title("Malicious URL Detection")
st.write("This app predicts whether a URL is malicious or not using Logistic Regression.")

url_input = st.text_input("Enter a URL:")

if url_input:
    features = {
        'use_of_ip_address': having_ip_address(url_input),
        'abnormal_url': abnormal_url(url_input),
        'count-www': count_www(url_input),
        'count@': count_atrate(url_input),
        'count_dir': no_of_dir(url_input),
        'count_embed_domian': no_of_embed(url_input),
        'short_url': shortening_service(url_input),
        'count-https': count_https(url_input),
        'count-http': count_http(url_input),
        'count%': count_per(url_input),
        'count?': count_ques(url_input),
        'count-': count_hyphen(url_input),
        'count=': count_equal(url_input),
        'url_length': url_length(url_input),
        'hostname_length': hostname_length(url_input),
        'sus_url': suspicious_words(url_input),
        'fd_length': fd_length(url_input),
        'tld_length': tld_length(get_tld(url_input, fail_silently=True)),
        'count-digits': digit_count(url_input),
        'count-letters': letter_count(url_input)
    }

 
    features_df = pd.DataFrame([features])

    
    prediction = classifier.predict(features_df)
    prediction_proba = classifier.predict_proba(features_df)

    
    if prediction[0] == 1:
        st.error("This URL is predicted to be MALICIOUS.")
    else:
        st.success("This URL is predicted to be BENIGN.")

    st.write(f"Probability: {prediction_proba[0][prediction[0]]:.2f}")