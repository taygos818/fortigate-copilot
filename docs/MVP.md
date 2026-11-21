# FortiGate Policy Analyzer — MVP

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
- published objects without a directly linked accepting policy (review indirect references before treating them as unused)

---

### 6. Risk Score

Simple scoring:

- ANY/ANY = +20
- WAN exposure = +20
- broad service = +10

Max = 100

---

### 7. Rule-based explanation layer

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
→ Rule-based Recommendations

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

## Current release boundary

The first public version uses deterministic rules. It does not call an AI model. It resolves address and VIP groups and reads interface roles, zones and SD-WAN to decide what faces the internet, but it does not evaluate policy order, schedules, routing or central NAT, and it cannot prove that a configuration is safe. Its score is an ordering aid.
