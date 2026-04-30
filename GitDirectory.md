# Pentesting When `.git` Directory Is Exposed

(CTF + Real-World Guide)

## 1. Confirm Exposure

Check if the `.git` directory is accessible:

```txt
http://target.com/.git/
http://target.com/.git/config
http://target.com/.git/HEAD
```

If files are accessible or return valid responses, proceed.

## 2. Dump the Repository

Use automated tools:

### Option A: GitTools

```bash
git clone https://github.com/internetwache/GitTools.git
cd GitTools/Dumper
./gitdumper.sh http://target.com/.git/ output-dir
```

### Option B: git-dumper

```bash
git-dumper http://target.com/.git/ output-dir
```

## 3. Rebuild the Repository

Navigate to dumped files:

```bash
cd output-dir
git checkout .
```

If reconstruction fails:

```bash
git fsck
git log
```

Manually inspect `.git/objects` if needed.

## 4. Analyze the Codebase

### 4.1 Search for Secrets

Look for:

* API keys
* Database credentials
* Tokens and secrets

Commands:

```bash
grep -r "key" .
grep -r "password" .
grep -r "secret" .
```

### 4.2 Inspect Commit History

Secrets are often removed but still exist in history.

```bash
git log
git show <commit_id>
git log -p
```

### 4.3 Check Sensitive Files

Focus on:

* `.env`
* Configuration files (`config.php`, `settings.py`, etc.)
* SSH keys (`id_rsa`)
* Backup files
* Deployment configs

### 4.4 Understand Application Logic

Identify:

* Authentication flow
* Hidden or undocumented endpoints
* Debug/test routes
* API structure

## 5. Identify Vulnerabilities

Common findings:

* Hardcoded credentials
* Exposed admin panels
* Debug endpoints (`/debug`, `/test`)
* Insecure API endpoints

## 6. Extract Deleted or Historical Secrets

Search through commit diffs:

```bash
git log -p | grep -i password
```

Optional tools:

* trufflehog
* gitleaks

## 7. Attempt Credential Reuse / Lateral Movement

If credentials are found, test for:

* SSH access
* Database access
* Cloud services (AWS, GCP, etc.)
* Admin panel login

## 8. CTF vs Real-World Differences

### CTFs

* `.git` exposure is intentional
* Secrets are easy to identify
* Linear path: `.git -> credentials -> flag`

### Real-World

* Repository may be incomplete or corrupted
* Secrets may be outdated but still valid
* Requires deeper analysis and validation
* Must demonstrate real impact, not just exposure

## 9. Reporting (Real Pentesting)

Include:

* Confirmation of `.git` exposure
* Ability to reconstruct repository
* Evidence of sensitive data (examples)
* Potential impact (account takeover, data breach, RCE)
* Risk severity

## 10. Mitigation Recommendations

* Block access to `.git` directory

Apache:

```txt
RedirectMatch 404 /\.git
```

Nginx:

```txt
location ~ /\.git {
    deny all;
}
```

* Do not deploy `.git` to production
* Store secrets securely (environment variables, secret managers)

---
