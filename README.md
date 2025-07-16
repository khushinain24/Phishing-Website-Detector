# 🛡️ Phishing Website Detection Tool

A **smart and lightweight Python application** that detects potentially harmful or phishing websites using a hybrid approach of **rule-based heuristics** and **machine learning (ML)**. This tool is designed to promote cybersecurity awareness and help users avoid phishing scams with real-time risk analysis.

---

## 🔍 Features

- ✅ **Rule-Based Detection**  
  Analyzes URLs for suspicious patterns using heuristics based on domain structure, keywords, and TLDs.

- 🤖 **Machine Learning Support**  
  Trains a Random Forest classifier on a small URL dataset using both textual and numeric features.

- 💡 **Risk Scoring System**  
  Assigns a phishing **risk score (0–100)** based on detected anomalies and behaviors.

- 🧠 **Hybrid Verdict Engine**  
  Combines ML predictions (70% weight) with rule-based analysis (30%) for improved detection accuracy.

- 🖥️ **Dual Mode Operation**
  - Graphical Interface using **Tkinter** for intuitive local analysis
  - **Command-Line Interface** fallback for terminal-based environments (e.g., servers or Google Colab)

- 📁 **Self-Contained and Offline-Capable**  
  Ships with a sample training dataset and works offline after dependencies are installed.

---

## 🧪 How It Works

### 🔹 Rule-Based Detection

The rule-based engine evaluates URLs and computes a risk score based on a variety of phishing indicators:

- 🌐 Excessive subdomains (e.g., `login.verify.bank.example.com`)
- 🧮 Use of raw IP addresses (e.g., `http://192.168.0.1/login`)
- 🕵️ Suspicious keywords: `login`, `verify`, `account`, `secure`, `paypal`, etc.
- 🌍 Suspicious or uncommon TLDs: `.tk`, `.ga`, `.ml`, `.cf`, `.pp.ua`, etc.
- 📏 Very long or obfuscated URLs (length > 75–100 chars)
- 🔤 Unicode homograph attempts (e.g., Cyrillic characters like `а`, `е`, `о`)
- 🔒 Lack of HTTPS encryption
- 🔗 Use of URL shorteners (e.g., `bit.ly`, `tinyurl.com`)
- ❗ Numerous parameters or redirections (`=`, `&`, `?`, etc.)

A risk score **above 50** indicates potential phishing.

---

### 🔹 ML-Based Detection (Optional)

If trained, the ML model provides a second layer of defense using a Random Forest classifier:

#### 🔠 Character-Level TF-IDF
- Extracts character n-grams (2 to 4) to identify suspicious patterns in URLs.

#### 🔢 Numeric Feature Extraction
- URL length, domain/path/query lengths
- Special character counts: `.`, `-`, `_`, `@`, `=`, `?`, `&`, `%`, etc.
- Boolean flags: presence of IP address, HTTPS, subdomains, etc.

#### 🧪 Sample Dataset Included
- 10 legitimate URLs and 10 phishing URLs
- Can be extended with larger, custom datasets

#### 🔁 Hybrid Scoring System
- Combines both engines:
  - **ML Confidence** → 70% weight
  - **Rule-Based Risk Score** → 30% weight

---

## 📦 Installation

```bash
pip install scikit-learn numpy pandas
