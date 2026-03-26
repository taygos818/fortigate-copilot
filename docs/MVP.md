# FortiGate AI Copilot — MVP

## 🎯 Goal
Analyze FortiGate firewall configurations and identify risky exposure through:
- firewall policies
- virtual IPs (destination NAT)
- virtual servers (load balancers)

---

## 🚀 MVP Definition

### Supported Vendor
- FortiGate only

### Supported Config Sections
- config firewall policy
- config firewall vip
- config firewall virtual-server

---

## 🔧 Core Features

### 1. Parse Firewall Policies
Extract:
- policy id
- srcintf
- dstintf
- srcaddr
- dstaddr
- service
- action
- schedule
- status

---

### 2. Parse VIPs (Destination NAT)
Extract:
- name
- extip
- extintf
- mappedip
- extport
- mappedport

---

### 3. Parse Virtual Servers
Extract:
- name
- interface
- IP
- port
- basic configuration

---

### 4. Link Policies to Published Services

Rules:
- If policy.dstaddr matches VIP name → link
- If policy.dstaddr matches virtual server → link

Output:

VIP → policy mapping  
Virtual server → policy mapping  

---

### 5. Exposure Analysis

Detect:

- ANY/ANY rules
- WAN → internal exposure
- VIP exposed to "all"
- service = ALL
- unused VIPs (no policy)

---

### 6. Risk Score

Simple scoring:

- ANY/ANY = +20
- WAN exposure = +20
- broad service = +10

Max = 100

---

### 7. AI Explanation Layer

Input:
- structured findings

Output:
- risk explanation
- remediation steps
- priority order

---

## ❌ Out of Scope (MVP)

- multi-vendor support
- nested object resolution
- SNAT analysis
- routing/path validation
- UI polish
- auth/billing

---

## 🧱 Architecture

Pipeline:

Config Input  
→ Parser  
→ Object Models  
→ Linking Engine  
→ Findings Engine  
→ Risk Score  
→ AI Explanation  

---

## 🎯 Success Criteria

User can:

Paste FortiGate config  
↓  
Click analyze  
↓  
See:
- published services
- policy mappings
- risk findings
- recommendations  

---

## ▶️ NEXT STEP

Build FortiGate policy parser (`parsePolicies.ts`)