# False positives

## Per site false positive strings

You can use `false_positive_strings` key in the **`wp_sites` config file value** to ignore some warnings or alerts on a per site basis.
False positives messages will still be processed as infos with `[False positive]` prefix.

Use case: Vulnerabilities are found but WPScan can't determine plugin version, so all vulnerabilities are printed. If your plugin version is not vulnerable, add vulnerability title (start with plugin name) in the list of false positive in the `wp_sites` entry. You might have to add a lot of false positives if the plugin version could not be determined because all known vulnerabilities will be listed.

```ini
wp_sites=   [
        {   
            "url":"exemple.com",
            "false_positive_strings":[
                "Yoast SEO 1.2.0-11.5 - Authenticated Stored XSS",
                "Yoast SEO <= 9.1 - Authenticated Race Condition"
            ]
        },
        {   
            "url":"exemple2.com",
            "false_positive_strings":[
                "W3 Total Cache 0.9.2.4 - Username & Hash Extract",
                "W3 Total Cache - Remote Code Execution",
                "W3 Total Cache 0.9.4 - Edge Mode Enabling CSRF",
                "W3 Total Cache <= 0.9.4 - Cross-Site Request Forgery (CSRF)",
                "W3 Total Cache <=  0.9.4.1 - Weak Validation of Amazon SNS Push Messages",
                "W3 Total Cache <= 0.9.4.1 - Information Disclosure Race Condition",
                "W3 Total Cache 0.9.2.6-0.9.3 - Unauthenticated Arbitrary File Read",
                "W3 Total Cache < 0.9.7.3 - Cryptographic Signature Bypass",
                "W3 Total Cache <= 0.9.7.3 - Cross-Site Scripting (XSS)",
                "W3 Total Cache <= 0.9.7.3 - SSRF / RCE via phar"
            ]
        }
    ]
```

## Global false positive strings
False positives can also be applied to all websites at once.

**For security reasons, it is recommended to use per site false positives**.   

(WPWatcher was historically working with global false positives only)

Use cases: 
- You want to ignore all "Potential Vulnerability" (i.e. don't worry about the vulnerabilities found when WPScan can't determine plugin version).
- You want to ignore all "Upload directory has listing enabled" warnings or other hard-coded warnings.

**Note**: "No WPScan API Token given" warning is automatically ignored.

```ini
false_positive_strings=["No WPScan API Token given, as a result vulnerability data has not been output."]
```
Or pass values by arguments: `--fpstr String [String ...]`
