import pandas as pd
import numpy as np
import re
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from urllib.parse import urlparse
import pickle
import os
from datetime import datetime
from collections import Counter

# Machine Learning imports
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: Scikit-learn not available. Only rule-based detection will work.")

class RuleBasedDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'secure', 'account', 'update', 'confirm', 'verify', 'login', 'signin',
            'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google', 'ebay',
            'suspended', 'limited', 'expire', 'urgent', 'immediate', 'action'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pp.ua', '.3utilities.com']
        
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'ebay.com', 'twitter.com', 'instagram.com',
            'linkedin.com', 'github.com', 'stackoverflow.com'
        ]
    
    def detect(self, url):
        """Rule-based phishing detection"""
        risk_score = 0
        flags = []
        
        try:
            parsed_url = urlparse(url.lower())
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Check URL length
            if len(url) > 100:
                risk_score += 20
                flags.append("Extremely long URL")
            elif len(url) > 75:
                risk_score += 10
                flags.append("Very long URL")
            
            # Check for IP address instead of domain
            if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', domain):
                risk_score += 30
                flags.append("Uses IP address instead of domain name")
            
            # Check for suspicious keywords
            keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword in url.lower())
            if keyword_count > 0:
                risk_score += keyword_count * 15
                flags.append(f"Contains {keyword_count} suspicious keyword(s)")
            
            # Check for URL shorteners (potential redirect)
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
            if any(shortener in domain for shortener in shorteners):
                risk_score += 25
                flags.append("Uses URL shortener")
            
            # Check for suspicious TLDs
            if any(tld in domain for tld in self.suspicious_tlds):
                risk_score += 20
                flags.append("Uses suspicious top-level domain")
            
            # Check for too many subdomains
            subdomains = domain.split('.')
            if len(subdomains) > 4:
                risk_score += 15
                flags.append("Too many subdomains")
            
            # Check for suspicious characters
            suspicious_chars = ['@', '-', '_']
            char_count = sum(url.count(char) for char in suspicious_chars)
            if char_count > 5:
                risk_score += 10
                flags.append("Many suspicious characters")
            
            # Check for HTTPS
            if not url.startswith('https://'):
                risk_score += 15
                flags.append("Not using HTTPS")
            
            # Check for legitimate domains (reduce risk)
            if any(legit_domain in domain for legit_domain in self.legitimate_domains):
                risk_score = max(0, risk_score - 30)
                flags.append("Appears to be legitimate domain")
            
            # Check for homograph attacks (similar looking characters)
            suspicious_chars_unicode = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic lookalikes
            if any(char in url for char in suspicious_chars_unicode):
                risk_score += 25
                flags.append("Contains suspicious Unicode characters")
            
            # Check for excessive redirects or parameters
            if url.count('=') > 3 or url.count('&') > 3:
                risk_score += 10
                flags.append("Many URL parameters")
            
            is_phishing = risk_score > 50
            
            return {
                'is_phishing': is_phishing,
                'risk_score': min(risk_score, 100),
                'flags': flags,
                'confidence': min(risk_score / 100, 1.0)
            }
            
        except Exception as e:
            return {
                'is_phishing': True,
                'risk_score': 100,
                'flags': [f"Error parsing URL: {str(e)}"],
                'confidence': 1.0
            }

class PhishingDetector:
    def __init__(self):
        self.rule_based_model = RuleBasedDetector()
        self.ml_model = None
        self.vectorizer = None
        self.scaler = None
        self.model_trained = False
        
    def extract_url_features(self, url):
        """Extract numerical features from URL for ML model"""
        features = {}
        
        # Basic URL structure
        features['url_length'] = len(url)
        features['domain_length'] = len(urlparse(url).netloc)
        features['path_length'] = len(urlparse(url).path)
        features['query_length'] = len(urlparse(url).query)
        
        # Character counts
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['question_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        features['at_count'] = url.count('@')
        features['and_count'] = url.count('&')
        features['exclamation_count'] = url.count('!')
        features['space_count'] = url.count(' ')
        features['tilde_count'] = url.count('~')
        features['comma_count'] = url.count(',')
        features['plus_count'] = url.count('+')
        features['asterisk_count'] = url.count('*')
        features['hash_count'] = url.count('#')
        features['dollar_count'] = url.count('$')
        features['percent_count'] = url.count('%')
        
        # Boolean features (converted to int)
        features['has_ip'] = int(bool(re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', url)))
        features['has_https'] = int(url.startswith('https://'))
        features['has_www'] = int('www.' in url)
        features['has_subdomain'] = int(len(urlparse(url).netloc.split('.')) > 2)
        
        # Suspicious patterns
        features['has_suspicious_words'] = int(bool(re.search(
            r'(secure|account|update|confirm|verify|login|signin|bank|paypal|amazon|microsoft|apple|google)', 
            url, re.IGNORECASE)))
        
        return list(features.values())
    
    def train_ml_model(self, urls, labels):
        """Train machine learning model with URL data"""
        if not ML_AVAILABLE:
            print("Cannot train ML model: scikit-learn not available")
            return False
            
        try:
            # Extract features
            print("Extracting features...")
            features = [self.extract_url_features(url) for url in urls]
            
            # Prepare text features
            self.vectorizer = TfidfVectorizer(max_features=1000, analyzer='char', ngram_range=(2, 4))
            text_features = self.vectorizer.fit_transform(urls).toarray()
            
            # Combine numerical and text features
            numerical_features = np.array(features)
            self.scaler = StandardScaler()
            numerical_features = self.scaler.fit_transform(numerical_features)
            
            combined_features = np.hstack([numerical_features, text_features])
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                combined_features, labels, test_size=0.2, random_state=42
            )
            
            # Train model
            print("Training model...")
            self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.ml_model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.ml_model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            print(f"Model accuracy: {accuracy:.2f}")
            
            self.model_trained = True
            return True
            
        except Exception as e:
            print(f"Error training ML model: {e}")
            return False
    
    def predict_ml(self, url):
        """Predict using ML model"""
        if not self.model_trained or not ML_AVAILABLE:
            return None, 0.0
            
        try:
            # Extract features
            numerical_features = np.array([self.extract_url_features(url)])
            numerical_features = self.scaler.transform(numerical_features)
            
            text_features = self.vectorizer.transform([url]).toarray()
            combined_features = np.hstack([numerical_features, text_features])
            
            # Predict
            prediction = self.ml_model.predict(combined_features)[0]
            probability = self.ml_model.predict_proba(combined_features)[0]
            
            return prediction, max(probability)
            
        except Exception as e:
            print(f"Error in ML prediction: {e}")
            return None, 0.0
    
    def detect_phishing(self, url):
        """Main detection function combining rule-based and ML approaches"""
        results = {}
        
        # Rule-based detection
        rule_result = self.rule_based_model.detect(url)
        results['rule_based'] = rule_result
        
        # ML detection
        if self.model_trained:
            ml_prediction, confidence = self.predict_ml(url)
            results['ml_prediction'] = ml_prediction
            results['ml_confidence'] = confidence
        else:
            results['ml_prediction'] = None
            results['ml_confidence'] = 0.0
        
        # Combined decision
        if results['ml_prediction'] is not None:
            # If ML model is available, use weighted combination
            ml_weight = 0.7
            rule_weight = 0.3
            
            ml_score = 1 if results['ml_prediction'] == 1 else 0
            rule_score = 1 if results['rule_based']['is_phishing'] else 0
            
            combined_score = (ml_score * ml_weight) + (rule_score * rule_weight)
            results['final_prediction'] = combined_score > 0.5
            results['confidence'] = combined_score
        else:
            # Use only rule-based detection
            results['final_prediction'] = results['rule_based']['is_phishing']
            results['confidence'] = results['rule_based']['risk_score'] / 100
        
        return results
    
    def train_sample_model(self):
        """Train ML model with sample data for command-line interface"""
        if not ML_AVAILABLE:
            print("Scikit-learn not available. Cannot train ML model.")
            return False
        
        # Sample training data
        sample_urls = [
            # Legitimate URLs
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.amazon.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.github.com",
            "https://www.stackoverflow.com",
            "https://www.wikipedia.org",
            "https://www.youtube.com",
            "https://www.twitter.com",
            
            # Phishing URLs (examples)
            "http://secure-paypal-update.tk/login",
            "https://amazon-security-alert.ml/verify",
            "http://microsoft-account-suspended.ga/signin",
            "https://apple-id-locked.cf/unlock",
            "http://facebook-security-check.pp.ua/login",
            "https://google-verify-account.3utilities.com/confirm",
            "http://192.168.1.100/banking/login.php",
            "https://www.g00gle.com/accounts/signin",
            "http://paypal-urgent-action-required.com/login",
            "https://amazon.security-update.info/verify-account"
        ]
        
        # Labels: 0 = legitimate, 1 = phishing
        sample_labels = [0] * 10 + [1] * 10
        
        return self.train_ml_model(sample_urls, sample_labels)

class PhishingGUI:
    def __init__(self):
        self.detector = PhishingDetector()
        self.setup_gui()
        self.history = []
        
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Phishing Website Detection Tool")
        self.root.geometry("800x700")
        self.root.configure(bg='#f0f0f0')
        
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        header_frame.pack(fill='x', pady=(0, 20))
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🛡️ Phishing Website Detector", 
                              font=('Arial', 18, 'bold'), fg='white', bg='#2c3e50')
        title_label.pack(expand=True)
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20)
        
        # URL input section
        input_frame = tk.LabelFrame(main_frame, text="URL Analysis", font=('Arial', 12, 'bold'),
                                   bg='#f0f0f0', fg='#2c3e50')
        input_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(input_frame, text="Enter URL to check:", font=('Arial', 10),
                bg='#f0f0f0').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.url_entry = tk.Entry(input_frame, font=('Arial', 10), width=70)
        self.url_entry.pack(padx=10, pady=(0, 10), fill='x')
        self.url_entry.bind('<Return>', lambda e: self.check_url())
        
        button_frame = tk.Frame(input_frame, bg='#f0f0f0')
        button_frame.pack(pady=(0, 10))
        
        self.check_button = tk.Button(button_frame, text="🔍 Check URL", 
                                     command=self.check_url, font=('Arial', 10, 'bold'),
                                     bg='#3498db', fg='white', padx=20)
        self.check_button.pack(side='left', padx=5)
        
        self.clear_button = tk.Button(button_frame, text="🗑️ Clear", 
                                     command=self.clear_results, font=('Arial', 10),
                                     bg='#95a5a6', fg='white', padx=20)
        self.clear_button.pack(side='left', padx=5)
        
        # Results section
        results_frame = tk.LabelFrame(main_frame, text="Analysis Results", 
                                     font=('Arial', 12, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        results_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, 
                                                     font=('Courier', 9), bg='#ffffff')
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Training section
        training_frame = tk.LabelFrame(main_frame, text="ML Model Training", 
                                      font=('Arial', 12, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        training_frame.pack(fill='x')
        
        self.train_button = tk.Button(training_frame, text="🤖 Train ML Model with Sample Data", 
                                     command=self.train_model, font=('Arial', 10, 'bold'),
                                     bg='#e74c3c', fg='white', padx=20)
        self.train_button.pack(pady=10)
        
        # Status section
        self.status_label = tk.Label(main_frame, text="Ready", font=('Arial', 9),
                                    bg='#f0f0f0', fg='#7f8c8d')
        self.status_label.pack(pady=(10, 0))
        
    def check_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL to check.")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        self.status_label.config(text="Analyzing URL...", fg='#f39c12')
        self.root.update()
        
        try:
            results = self.detector.detect_phishing(url)
            self.display_results(url, results)
            self.history.append((url, results, datetime.now()))
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        
        self.status_label.config(text="Analysis complete", fg='#27ae60')
    
    def display_results(self, url, results):
        self.results_text.delete(1.0, tk.END)
        
        # Header
        self.results_text.insert(tk.END, "="*80 + "\n")
        self.results_text.insert(tk.END, f"PHISHING DETECTION RESULTS\n")
        self.results_text.insert(tk.END, f"Analyzed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.results_text.insert(tk.END, "="*80 + "\n\n")
        
        # URL
        self.results_text.insert(tk.END, f"URL: {url}\n\n")
        
        # Final verdict
        verdict = "🚨 PHISHING DETECTED" if results['final_prediction'] else "✅ LIKELY SAFE"
        confidence = results['confidence'] * 100
        
        self.results_text.insert(tk.END, f"VERDICT: {verdict}\n")
        self.results_text.insert(tk.END, f"Confidence: {confidence:.1f}%\n\n")
        
        # Rule-based analysis
        self.results_text.insert(tk.END, "📋 RULE-BASED ANALYSIS:\n")
        self.results_text.insert(tk.END, "-" * 40 + "\n")
        
        rule_results = results['rule_based']
        rule_verdict = "Phishing" if rule_results['is_phishing'] else "Safe"
        self.results_text.insert(tk.END, f"Verdict: {rule_verdict}\n")
        self.results_text.insert(tk.END, f"Risk Score: {rule_results['risk_score']}/100\n")
        
        if rule_results['flags']:
            self.results_text.insert(tk.END, "\nSuspicious Patterns Detected:\n")
            for i, flag in enumerate(rule_results['flags'], 1):
                self.results_text.insert(tk.END, f"  {i}. {flag}\n")
        
        # ML analysis
        if results['ml_prediction'] is not None:
            self.results_text.insert(tk.END, f"\n🤖 MACHINE LEARNING ANALYSIS:\n")
            self.results_text.insert(tk.END, "-" * 40 + "\n")
            ml_verdict = "Phishing" if results['ml_prediction'] == 1 else "Safe"
            ml_confidence = results['ml_confidence'] * 100
            self.results_text.insert(tk.END, f"Verdict: {ml_verdict}\n")
            self.results_text.insert(tk.END, f"Confidence: {ml_confidence:.1f}%\n")
        else:
            self.results_text.insert(tk.END, f"\n🤖 MACHINE LEARNING: Not available\n")
            self.results_text.insert(tk.END, "(Train the model first for ML-based detection)\n")
        
        # Recommendations
        self.results_text.insert(tk.END, f"\n💡 RECOMMENDATIONS:\n")
        self.results_text.insert(tk.END, "-" * 40 + "\n")
        
        if results['final_prediction']:
            self.results_text.insert(tk.END, "⚠️  DO NOT enter personal information on this website\n")
            self.results_text.insert(tk.END, "⚠️  Verify the URL by typing it manually\n")
            self.results_text.insert(tk.END, "⚠️  Check for HTTPS and proper domain spelling\n")
            self.results_text.insert(tk.END, "⚠️  Contact the organization directly if unsure\n")
        else:
            self.results_text.insert(tk.END, "✅ Website appears to be legitimate\n")
            self.results_text.insert(tk.END, "✅ Still verify sender if you arrived via email/message\n")
            self.results_text.insert(tk.END, "✅ Always use strong, unique passwords\n")
        
        self.results_text.insert(tk.END, "\n" + "="*80 + "\n")
    
    def train_model(self):
        if not ML_AVAILABLE:
            messagebox.showerror("Error", "Scikit-learn is not available. Cannot train ML model.")
            return
        
        self.status_label.config(text="Training ML model...", fg='#f39c12')
        self.root.update()
        
        success = self.detector.train_sample_model()
        
        if success:
            self.status_label.config(text="ML model trained successfully!", fg='#27ae60')
            messagebox.showinfo("Success", "Machine Learning model has been trained!\nYou can now use both rule-based and ML detection.")
        else:
            self.status_label.config(text="Failed to train ML model", fg='#e74c3c')
            messagebox.showerror("Error", "Failed to train the ML model. Check console for details.")
    
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.url_entry.delete(0, tk.END)
        self.status_label.config(text="Ready", fg='#7f8c8d')
    
    def run(self):
        self.root.mainloop()

def main():
    """Main function to run the phishing detection tool"""
    print("Phishing Website Detection Tool")
    print("=" * 50)
    
    # Check if running with GUI
    try:
        app = PhishingGUI()
        app.run()
    except Exception as e:
        print(f"GUI failed to start: {e}")
        print("Running in command-line mode...")
        
        # Command-line interface
        detector = PhishingDetector()
        
        print("\nCommands:")
        print("1. Enter URL to check")
        print("2. Type 'train' to train ML model with sample data")
        print("3. Type 'quit' to exit")
        
        while True:
            try:
                user_input = input("\n> ").strip()
                
                if user_input.lower() == 'quit':
                    break
                elif user_input.lower() == 'train':
                    print("Training ML model with sample data...")
                    success = detector.train_sample_model()
                    if success:
                        print("✅ Training completed successfully!")
                    else:
                        print("❌ Training failed. Check if scikit-learn is installed.")
                elif user_input:
                    if not user_input.startswith(('http://', 'https://')):
                        user_input = 'http://' + user_input
                    
                    results = detector.detect_phishing(user_input)
                    
                    print(f"\nURL: {user_input}")
                    print(f"Verdict: {'PHISHING' if results['final_prediction'] else 'SAFE'}")
                    print(f"Confidence: {results['confidence']*100:.1f}%")
                    
                    if results['rule_based']['flags']:
                        print("\nSuspicious patterns:")
                        for flag in results['rule_based']['flags']:
                            print(f"  - {flag}")
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()