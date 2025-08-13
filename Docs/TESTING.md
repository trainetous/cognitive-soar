
---

## **TESTING.md**

```markdown
# Test Cases

## **1. Benign URL Test**
**URL**: `https://docs.google.com/document/d/abc123`  
**Expected Results**:
- Classification: Benign
- Confidence: >70%
- No attribution
- Response: Basic monitoring recommended

## **2. State-Sponsored APT Pattern**
**URL**: `https://secure.swift.com.payment.verification.national-bank-update.org`  
**Expected Results**:
- Classification: Malicious (>90%)
- Attribution: State-Sponsored APT
- Key Features:
  - Long URL (length=2)
  - Multiple subdomains (subdomains=2)
  - Valid SSL (SSLfinal_State=1)
- Response: Incident response protocol + threat intel sharing

## **3. Organized Cybercrime Pattern**
**URL**: `http://192.168.1.1/paypal/login?sessionid=abc123`  
**Expected Results**:
- Classification: Malicious (>95%)
- Attribution: Organized Cybercrime
- Key Features:
  - IP in URL (ip_in_url=1)
  - Shortened path (path_length=1)
  - No SSL (SSLfinal_State=0)
- Response: Fraud alert + credential reset

## **4. Hacktivist Pattern**
**URL**: `https://free-tibet.org/protest-signup?activist=1`  
**Expected Results**:
- Classification: Malicious (80-90%)
- Attribution: Hacktivist
- Key Features:
  - Political keywords (has_political_keyword=1)
  - Mixed SSL (SSLfinal_State=0)
- Response: Communications monitoring

## **Verification Steps**
1. Check classification confidence exceeds thresholds
2. Confirm correct threat actor profile activation
3. Validate response plan matches threat type
4. Verify no false positives in benign cases
