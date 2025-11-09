# 🔥 Sigma2KQL Converter 🔥

We used an internal tool called Iku-blood to first blood this challenge. See [solve script](exploit.py) for solution.

```
12:07:40 PM (Iku-topp)
**Triggered fetching of fire challenges**

[Iku solving]

12:17:31 PM (Iku-topp)
Remote if you need: https://ikutoppene-ce17ceea-sigmaconverter.ept.gg

[Iku solving]

12:33:12 PM (Iku-blood)
Submitted correct flag to platform

12:33:21 PM (Iku-blood)
Found a SQL injection in portal/main/routes.py:206 (api_combined_rules_favorites_status) where user-controlled converted_kql_signature strings are concatenated into a LIKE filter without sanitisation, allowing injected SQL to execute.

Crafted a Sigma rule whose converted KQL signature closes the string, issues COMMIT, inserts a new admin user with a controlled bcrypt hash, and finishes with SELECT 1 so the request still returns rows—this works locally and on prod.

Automated the end-to-end attack in exploit.py: register/login, submit the malicious rule, toggle it as favourite to hit the vulnerable API, then authenticate to /admin/ with the inserted admin account and scrape the flag.

Flag

EPT{6929dec8-3312-4341-9ee6-75faacda2562}
```