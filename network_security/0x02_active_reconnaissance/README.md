# Active Reconnaissance Project

## Overview
In this project, I performed active reconnaissance techniques on the target `active.hbtn` to identify services, vulnerabilities, and sensitive information.

---

## Tools Used
- Nmap → Port scanning  
- Wappalyzer → Technology fingerprinting  
- Gobuster → Directory enumeration  
- SQLMap → SQL injection exploitation  

---

## Steps and What I Did

### 1. Port Scanning
I used Nmap to identify open ports on the target machine.
Result:
- Port 80 was open (HTTP)

---

### 2. Web Technology Identification
Using Wappalyzer, I identified the web server and technologies used on the website.

---

### 3. Source Code Inspection
I inspected the website source code and found a hidden comment containing a flag.

---

### 4. Vulnerable Page Discovery
I identified an injectable endpoint:
- `/product`

This endpoint was vulnerable to SQL Injection.

---

### 5. SQL Injection Exploitation
Using SQLMap, I:
- Extracted the database name: `active.hbtn`
- Found all tables:
  - Users
  - Admins
  - Products
  - Orders

---

### 6. Data Extraction
I dumped database contents and retrieved:
- Usernames and passwords
- Admin credentials

This allowed me to understand how the backend worked.

---

### 7. Directory Enumeration
Using Gobuster, I discovered hidden directories such as:
- `/admin`

---

### 8. Admin Panel Access
I accessed the admin panel and found a flag exposed directly on the page.

---

## Key Learnings

- Active reconnaissance involves interacting directly with the target.
- Tools help automate tasks, but analysis is essential.
- SQL Injection can expose sensitive backend data.
- Hidden directories can reveal admin panels and sensitive pages.
- Not all flags are obvious — some require analysis of data patterns.

---

## Conclusion
This project helped me understand the full workflow of a basic web pentest:

``
