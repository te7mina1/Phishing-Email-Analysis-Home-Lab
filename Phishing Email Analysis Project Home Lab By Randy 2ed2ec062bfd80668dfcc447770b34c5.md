# Phishing Email Analysis Project | Home Lab

![goodPhish.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/goodPhish.png)

## Overview

This document analyzes a suspicious email titled **"New Year Free Gift 🎁"** that was automatically flagged by Gmail as phishing. The goal is to clearly explain what is happening in each screenshot and highlight key indicators of a phishing attempt from a SOC / security analysis perspective.

## Understanding Phishing

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image.png)

- **Phishing** is a type of **social engineering** attack where attackers **impersonate legitimate entities**, such as banks, companies, or government agencies, **to trick recipients into revealing sensitive information**, such as usernames, passwords, credit card numbers, or other personal information.
- Phishing emails often contain **urgent messages, alarming statements, or enticing offers** to prompt recipients to click on malicious links or download infected attachments. These emails can be highly convincing, often using logos, email templates, and language that mimic those of legitimate organizations. Phishing emails are a common method for distributing malware or gaining unauthorized access to sensitive information

## Introduction

I tried checking my **spam** mail, because I was three (3) unread mail which I wanted to check and why it was in my spam.

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%201.png)

In the above image, we can see my spam messages;

- one form **OSINT Industries**, where I practice my OSINT skills and ctf. No idea why it was flagged as spam, but after opening it, i realized why it was flagged as spam.

## Why is this message in spam?

This message is similar to messages that were identified as spam in the past.

- the other spam message from **ISC2,** where I am planning of taking the certification
- and finally, our real phishing message, which indicates it’s from **Google.** I was figuring out why Google will give a **New Year Free Gift.**

So let’s get into it…

## Practical Demo

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%202.png)

## Gmail Security Warning Banner

**What is shown:**

- A large red banner stating **"This message might be dangerous"**.
- Gmail warns that similar messages are used to steal personal information.
- The email is addressed generically as **“Dear Customer”**, not by name.

**Analysis:**

- Gmail’s automated detection engine has identified phishing indicators.
- Users are advised not to click links, download attachments, or reply.

 This is a strong initial indicator that the email is malicious.

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%203.png)

## Suspicious Email Content and Attachment Block

**What is happening:**

- The sender claims to be **“The Team, Shell Ghana”**, which is unrelated to Google.
- Gmail blocks the attachment and displays a warning:
    
    > “Downloading this attachment is disabled. This email has been identified as phishing.”
    > 

**Why this matters:**

- Generic greetings are a common phishing technique.
- Claiming to represent a **trusted brand (Shell Ghana)** while sending from Google is a **brand impersonation tactic**.
- Blocking the attachment prevents possible **malware delivery**.

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%204.png)

## Email Header / Sender Details

**What is happening:**

- The email appears to be sent from:
    
    ```
    Google <no.replygoogle4@gmail.com>
    ```
    
- The domain used is **gmail.com**, not an official Google domain (e.g., `google.com`).

**Why this matters:**

- Attackers use **look-alike email addresses** to trick users.
- The sender name says “Google”, but the actual email address is **not legitimate**.
- This is a classic case of **email spoofing / impersonation**.

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%205.png)

Now the step to to view the raw headers of the email message, is to navigate to the **Show original** option.

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%206.png)

The few important part of the email headers to view in an email investigation.

- the **Message ID**
- the date, if there is an alteration before getting to your inbox
- the **sender** and **recipient**
- and the **Authentication** results; **the SPF, DKIM and DMARC**

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%207.png)

**Key Headers**

## Sender Identity & Display Name Abuse

### Header

```
From: GoogIe<no.replygooge4@gmail.com>
```

### Analysis

- The display name **“GoogIe”** uses a **homo-glyph attack**:
    - Uppercase **“I”** instead of lowercase **“l”**
- Gmail address: `no.replygooge4@gmail.com`
    - Misspelling of “google”
    - Numeric suffix often used in phishing campaigns

**Clear impersonation of Google branding**

## Authentication Results

### Authentication Headers

```
SPF: pass
DKIM: pass
DMARC: pass (p=NONE sp=QUARANTINE)
```

### Analysis

- **SPF: PASS** – Gmail servers are authorized to send for `gmail.com`
- **DKIM: PASS** – Message was legitimately signed by Gmail
- **DMARC: PASS** – Domain alignment succeeded

Upon seeing the message and the gmail address, I knew this email was going to pass the Authentication Results.

> NOTE:  Authentication success **does NOT mean the email is safe**.
> 
> 
> It only confirms the message was sent from Gmail — **not that the sender is trustworthy**.
> 
>  **This is an example of “Authenticated Phishing”**
> 

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%208.png)

```bash
Received: from mail-sor-f41.google.com [209.85.220.41]
Return-Path: <no.replygooge4@gmail.com>
```

### Analysis

- Email originated from **Google’s own mail servers** (`209.85.220.41`).

```bash
localhost:~$ whois 209.85.220.41

NetRange:       209.85.128.0 - 209.85.255.255
CIDR:           209.85.128.0/17
NetName:        GOOGLE      
Organization:   Google LLC (GOGL)
RegDate:        2006-01-13
Updated:        2012-02-24
Ref:            https://rdap.arin.net/registry/ip/209.85.128.0
OrgName:        Google LLC
OrgId:          GOGL
Address:        1600 Amphitheatre Parkway
City:           Mountain View
```

- This indicates the attacker used a **compromised or attacker-controlled Gmail account**.
- Use of legitimate infrastructure helps bypass traditional email security controls.

 **Technically legitimate source**

 **Malicious sender intent**

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%209.png)

Message Date and Time are also important when investigating emails as it indicates **delayed phishing** as a deceptive tactic used by attackers to bypass email security filters.

### Analysis

- No timestamp spoofing or replay indicators

 **No temporal anomalies**

- For the **Content-Type,** email message contains:
    - Plain text
    - HTML
    - Inline image (JPEG)
- Common structure for phishing emails to increase legitimacy
- Inline images often used to bypass text-based detection

These are **common phishing techniques.**

## Header Analysis with Online Automated Tools - MX ToolBox and EML Analyzer

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%2010.png)

Pasting the whole email header into the MX ToolBox to translate email headers into a human readable format and analyze the results of the email.

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%2011.png)

This image provides a high-level "pass/fail" report of the email's security credentials.

- **DMARC Compliant (FAIL)**.
- **The Breakdown:**
    - **SPF (Pass):** The email came from an authorized server.
    - **DKIM Alignment (Pass):** The digital signature claims to be from the correct domain.
    - **DKIM Authentication (FAIL):** Even though the signature *looks* like it's from the right place, the "digital fingerprint" doesn't match the content.

Finally, because the DKIM authentication failed, the overall DMARC check failed. This is a major red flag for a phishing attempt or a tampered email.

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%2012.png)

**The Critical Failure:** **"Body Hash Did Not Verify."**

- Here we can see the **body hash** upon sending the email message does not match after it was received.

In the main message, there was no image showing after the **greeting, Dear Customer.**

> NOTE: relying on one tool as a SOC is not a good practice. So i decided to use a different email analyzer tool, **EML Analyzer.**
> 

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%2013.png)

This part of the results from the EML Analyzer gave us the full body of the email, making me think why the body hash failed.

**Email Body Failure**

- **Brand Impersonation**: claiming to be “**Shell Ghana**”
- **Generic Greetings**: using “**Dear Customer**” instead of the right name of the user, eg. **Dear Michael**
- **Reward Lure**: **FREE premium  subscription**
- **Spelling Errors, Punctuation and Grammar**: “**Aniversary**” instead of **Anniversary**
- **Suspicious Links Structure**: the use of **@**
- **Awkward Phrasing and Generic Closing**

All these and more are **red flags** you should look out for in phishing messages.

## URL Analysis - Critical Indicator

Here I did a simple **url analysis** using **Virus Total and Hybrid Analysis tools.**

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%2014.png)

This is a result from the **EML Analyzer tool** where it automatically extracted the emails and domains from the whole URL as shown above.

 ****

**Email Body URL**

```bash
https://shell.com@tfgz.xyz/anniversary-prizes-26
```

### Analysis

- Uses **username@host URL obfuscation**
    - it shows an example of a suspicious link, noticing the unusual format with **@** and a weird domain (**tfgz**.**xyz**). Legit sites usually look cleaner.
    - `shell.com` is NOT the domain
    - Actual domain: **tfgz.xyz**

In most of my view of phishing links, `.xyz` TLD is a **high-risk** and commonly abused in most of them (phishing).

- The phishing link claimed brand, **Shell Ghana.**

**High-confidence phishing indicator**

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%2015.png)

In the scan, **Virus Total** proved the link being dangerous;

- 2 vendors flagged as “**Suspicious”**
- and 1 vendor flagged as **“Malicious”**

this alone gives us a reason that the url is **not safe.** 

> NOTE: relying on one tool as a SOC Analyst, is not really a safe act, although there is a suspicious or malicious detection of the first tool. So, in my case, I tried using a different analysis tool, **Hybrid Analysis.**
> 

![image.png](Phishing%20Email%20Analysis%20Project%20Home%20Lab%20By%20Randy/image%2016.png)

Upon scanning with the second analysis tool, it proved the same result as **Malicious** and also giving us some details about the link;

- suspicious redirect
- malware and phishing, which we are already aware of
- and the size of the link

all these details helps SOC Analyst to create **Indicator of Compromise (IoC)**

**Trusted level: do not trust** 

Finally, an email message hint to know about.

> **no-reply email address** does not receive any incoming emails. It is typically used for sending mail that do not require a reply; such as transactional emails etc.
> 

## Final Verdict

### Classification

**Phishing Email**

### Why This Email Is Malicious (Despite Passing Auth)

- Attacker leveraged **legitimate Gmail infrastructure**
- Used **look-alike sender name**
- Embedded **deceptive URL structure**
- Performed **brand impersonation**
- Targeted users with **reward-based lure**

### Key SOC Lesson

> Email authentication validates infrastructure, not intent.
> 
> 
> This case demonstrates why SOC analysts must analyze **headers + content + URLs together**, not authentication alone.
> 
> **AI is a powerful tool,** and I use it in most of my workflows.
> 

**Finally, this is how I went about analyzing the entire email message.**

**Thank you**
