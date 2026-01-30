
# Phishing Email Analysis Project | Home Lab

## 🔍 Project Overview

This project provides a hands-on walkthrough for analyzing phishing email headers — a core skill for Security Operations Center (SOC) analysts, incident responders, and email security professionals. The lab focuses on extracting, interpreting, and correlating email header fields to identify malicious indicators, trace email routing paths, and detect spoofing or impersonation attempts.


## 🎯 Why This Matters

Email remains one of the most common attack vectors for:

* Phishing campaigns
* Business Email Compromise (BEC)
* Malware and credential delivery

By understanding email headers, analysts can:

* Trace an email’s true origin and delivery path
* Validate sender authenticity using SPF, DKIM, and DMARC
* Detect spoofing, impersonation, and authenticated phishing
* Extract forensic artifacts for investigations and threat intelligence


## 🛠️ Tools Used

* Email clients/services (Gmail, Outlook, Thunderbird)
* Email header analysis tools (MXToolbox, EML Analyzer)
* Virus Total
* Hybrid Analysis
* Virtual lab environment (secured analysis setup)


## 🚀 Walkthrough Steps

### Step 1: Extract Full Email Headers

Obtain the complete raw email headers from the email client (e.g., *Show original* in Gmail) and preserve them for analysis.

### Step 2: Analyze Email Routing

Review the `Received` headers from bottom to top to trace the email’s path, identify sending servers, IP addresses, and detect abnormal routing behavior.

### Step 3: Validate Email Authentication

Examine SPF, DKIM, and DMARC results to determine whether the sender domain and sending infrastructure are authorized and aligned.

### Step 4: Inspect Sender Identity & Header Anomalies

Analyze fields such as `From`, `Return-Path`, `Reply-To`, and display names to identify spoofing, lookalike domains, or impersonation attempts.

### Step 5: Correlate Header Findings with Email Content

Compare header analysis with email body indicators such as malicious URLs, brand impersonation, social engineering language, and attachment behavior to reach a final verdict.


## ✅ Outcome

This project demonstrates how phishing emails can appear legitimate by passing authentication checks while still being malicious. It reinforces the importance of combining **header analysis, content inspection, and contextual reasoning** when handling email-based threats in a SOC environment.



## 📌 Key Takeaway

> Passing SPF, DKIM, and DMARC does not guarantee an email is safe. Analysts must evaluate intent, identity, and behavior — not authentication alone.

