#! /usr/bin/env python3
# 
# WPScan output parser
# 
# Authors: Florian Roth, Tristan Landès
#
# DISCLAIMER - USE AT YOUR OWN RISK.
#
# You can import this package into your application and call `parse_results` method.
#   from wpwatcher.parser import parse_results
#   (messages, warnings, alerts) = parse_results(wpscan_output_string)

# Parse know vulnerabilities
    # Parse vulnerability data and make more human readable.
    # NOTE: You need an API token for the WPVulnDB vulnerability data.

"""
All the WPScan fields for the JSON output in the views/json folders at:

https://github.com/wpscanteam/CMSScanner/tree/master/app/views/json
https://github.com/wpscanteam/wpscan/tree/master/app/views/json

Here are some other inspirational ressources found about parsing wpscan json

Generates a nice table output (Rust code) 
    https://github.com/lukaspustina/wpscan-analyze
    Parser code: 
        https://github.com/lukaspustina/wpscan-analyze/blob/master/src/analyze.rs
Python parser (do not parse for vulnerable theme or outdated warnings) 
    https://github.com/aaronweaver/AppSecPipeline/blob/master/tools/wpscan/parser.py
Vulcan wpscan (Go) 
    https://github.com/adevinta/vulcan-checks/blob/master/cmd/vulcan-wpscan/wpscan.go
    Great job listing all the fields, is the list complete ?
Dradis ruby json Parser 
    https://github.com/dradis/dradis-wpscan/blob/master/lib/dradis/plugins/wpscan/importer.rb : 
    No warnings neither but probably the clearest code

Ressource PArsing CLI output:
    List of all icons: https://github.com/wpscanteam/CMSScanner/blob/master/app/formatters/cli.rb
"""

import json
import re
from abc import ABC, abstractmethod

def parse_results(wpscan_output, false_positives_strings=[], verbose=False):
    """Helper function to parse any WPScan output"""
    ( messages, warnings, alerts ) = ([],[],[])
    is_json=False
    try:
        data=json.loads(wpscan_output)
        is_json=True
    except ValueError: pass
    if is_json: 
        parser=WPScanJsonParser(data, false_positives_strings)
        (messages, warnings, alerts) = parser.get_infos(verbose), parser.get_warnings(verbose), parser.get_alerts(verbose)
    else:  
        (messages, warnings, alerts)=parse_cli(wpscan_output, false_positives_strings)
    return (messages, warnings, alerts) 


########################  JSON PARSING ######################


class Component(ABC):
    def __init__(self, data): 
        """Base abstract class for all WPScan JSON components"""
        if not data: data={}
        self.data=data

    @abstractmethod
    def get_infos(self, verbose=False):
        pass

    @abstractmethod
    def get_warnings(self, verbose=False):
        pass

    @abstractmethod
    def get_alerts(self, verbose=False):
        pass

class WPScanJsonParser(Component):
    
    def __init__(self, data, false_positives_strings=None):
        """Main interface to parse WPScan JSON data"""
        if not data: data={}
        super().__init__(data)

        self.false_positives_strings=false_positives_strings if false_positives_strings else []
        self.components=[]
        # Add WPVersion
        if data.get('version', None):
            self.components.append(WPVersion(data.get('version')))
        # Add MainTheme
        if data.get('main_theme', None):
            self.components.append(MainTheme(data.get('main_theme')))
        # Add Plugins
        self.components.extend([Plugin(data.get('plugins').get(slug)) for slug in data.get('plugins', {})])
        # Add Themes
        self.components.extend([Theme(data.get('themes').get(slug)) for slug in data.get('themes', {})])
        # Add Interesting findings
        self.components.extend([InterestingFinding(finding) for finding in data.get('interesting_findings', [])])
        # Add Timthumbs
        self.components.extend([Timthumb(url, data.get('timthumbs').get(url)) for url in data.get('timthumbs', {})])
        # Add DBExport
        self.components.extend([DBExport(url, data.get('db_exports').get(url)) for url in data.get('db_exports', {})])
        # Add Users
        self.components.extend([User(url, data.get('users').get(url)) for url in data.get('users', {})])
        # Add Password attack
        if data.get('password_attack', None):
            self.components.append(PasswordAttack(data.get('password_attack')))
        # Add Not fully configured
        if data.get('not_fully_configured', None):
            self.components.append(NotFullyConfigured(data.get('not_fully_configured')))
        # Add Medias
        self.components.extend([Media(url, data.get('medias').get(url)) for url in data.get('medias', {})])
        # Add Config backups
        self.components.extend([ConfigBackup(url, data.get('config_backups').get(url)) for url in data.get('config_backups', {})])
        # Add VulnAPI 
        self.components.append(VulnAPI(data.get('vuln_api', {})))
        # Add 
        if data.get('banner', None):
            self.components.append(Banner(data.get('banner')))
        # Add ScanStarted
        self.components.append(ScanStarted(data))
        # Add ScanFinished
        self.components.append(ScanFinished(data))

    def get_infos(self, verbose=False):
        """Add false positives as infos with "[False positive]" prefix"""
        infos=[]
        for component in self.components:
            cinfos=component.get_infos(verbose)
            infos.extend(cinfos)
            for alert in component.get_alerts(verbose)+component.get_warnings(verbose):
                if self.is_false_positive(alert, self.false_positives_strings):
                    infos.append("[False positive]\n"+alert)

        return infos

    def get_warnings(self, verbose=False):
        """Igore false positives and automatically remove special warning if all vuln are ignored"""
        warnings=[]
        for component in self.components:
            all_warnings=component.get_warnings(verbose)
            component_warnings=self.ignore_false_positives(all_warnings, self.false_positives_strings)
            # Automatically remove special warning if all vuln are ignored
            if len(component_warnings)==1 and 'The version could not be determined' in component_warnings[0]:
                component_warnings=[]

            warnings.extend(component_warnings)
            
        return warnings

    def get_alerts(self, verbose=False):
        """Igore false positives"""
        alerts=[]
        for component in self.components:
            alerts.extend(self.ignore_false_positives(component.get_alerts(verbose), self.false_positives_strings))
        return alerts

    @staticmethod
    def ignore_false_positives(messages, false_positives_strings):
        """Process false positives"""
        for alert in messages:
            if WPScanJsonParser.is_false_positive(alert, false_positives_strings):
                messages.remove(alert)
        return messages

    @staticmethod
    def is_false_positive(string, false_positives_strings):
        """False Positive Detection"""
        for fp_string in false_positives_strings:
            if fp_string in string:
                return True

class Vulnerability(Component):
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""
        if not data: data={}
        super().__init__(data)

        self.title=data.get('title', None)
        self.cvss=data.get('cvss', None)
        self.fixed_in=data.get('fixed_in', None)
        self.references=data.get('references', None)

    def get_alerts(self, verbose=False):
        """Return 1 alert. First line of alert string contain the vulnerability title. Process CVE and WPVulnDB references to add links"""
        alert="Vulnerability: {}".format(self.title)

        if self.cvss: 
            alert+='\nCVSS: {}'.format(self.cvss)
        if self.fixed_in: 
            alert+='\nFixed in: {}'.format(self.fixed_in)
        else:
            alert+='\nNot fixed yet'
        if self.references: 
            alert+='\nReferences: '
            for ref in self.references:
                if ref == 'cve':
                    for cve in self.references[ref]: 
                        alert+="\n- CVE: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{}".format(cve)
                elif ref == 'wpvulndb': 
                    for wpvulndb in self.references[ref]:
                        alert+="\n- WPVulnDB: https://wpvulndb.com/vulnerabilities/{}".format(wpvulndb)
                else:
                    for link in self.references[ref]:
                        alert+="\n- {}: {}".format(ref.title(), link)

        return([alert])

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_infos(self, verbose=False):
        """Return empty list"""
        return []

class Finding(Component):
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""
        if not data: data={}
        super().__init__(data)

        self.found_by=data.get("found_by", None)
        self.confidence=data.get("confidence", None)
        self.interesting_entries=data.get("interesting_entries", None)
        self.confirmed_by=data.get("confirmed_by", None)
        self.vulnerabilities=[Vulnerability(vuln) for vuln in data.get("vulnerabilities", [])]

    def get_alerts(self, verbose=False):
        """Return list of vulnerabilities"""
        alerts=[]
        for v in self.vulnerabilities:
            alerts.extend(v.get_alerts(verbose))
        return alerts

    def get_infos(self, verbose=False):
        """Return 1 info"""
        info=""
        if self.found_by:
            info+="Found by: {} ".format(self.found_by)
        if self.confidence: 
            info+="(confidence: {})".format(self.confidence)
        if self.interesting_entries and verbose: 
            info+="\nInteresting entries: \n- {}".format('\n- '.join(self.interesting_entries))
        if self.confirmed_by and verbose: 
            info+="\nConfirmed by: "
            for entry in self.confirmed_by:
                info+="\n- {} ".format(entry)
                if self.confirmed_by[entry].get('confidence', None): 
                    info+="(confidence: {})".format(self.confirmed_by[entry]['confidence'])
                if self.confirmed_by.get("interesting_entries", None):
                    info+="\n  Interesting entries: \n  - {}".format('\n  - '.join(self.confirmed_by.get("interesting_entries")))
        return [info]

class WPVersion(Finding):
    
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb"""
        if not data: data={}
        super().__init__(data)
        self.number=data.get('number', None)
        self.release_date=data.get('release_date', None)
        self.status=data.get('status', None)

    def _get_infos(self, verbose=False):
        """Return 1 info"""
        if self.number:
            info="Wordpress Version: {}".format(self.number)
            if self.release_date:
                info+="\nRelease Date: {}".format(self.release_date)
            if self.status:
                info+="\nStatus: {}".format(self.status.title())  
        else:
            info="The WordPress version could not be detected"
       
        info+="\n{}".format(super().get_infos(verbose)[0])

        return [info]

    def get_infos(self, verbose=False):
        """Return 0 or 1 info, no infos if WPVersion triggedred warning, use get_warnings()"""
        if not self.get_warnings(verbose):
            return self._get_infos(verbose) 
        else:
            return []

    def get_warnings(self, verbose=False):
        """Return 0 or 1 warning"""
       
        if self.status=="insecure":
            warning=self._get_infos(verbose)[0]
            warning+="\nWarning: Outdated WordPress version"
            return [warning]
        else:
            return []

    def get_alerts(self, verbose=False):
        """Return Wordpress Version vulnerabilities"""
        return [ "Vulnerable Wordpress: {}".format(alert) for alert in super().get_alerts(verbose) ]

class WPItemVersion(Finding):
    
    def __init__(self, data): 
        """ Themes, plugins and timthumbs Version. From:
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb
        """
        if not data: data={}
        super().__init__(data)
        self.number=data.get('number', None)
    
    def get_alerts(self, verbose=False):
        """Return any item version vulnerabilities"""
        return super().get_alerts(verbose)

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_infos(self, verbose=False):
        """Return 0 or 1 info. No infos if version cound not be recognized"""
        if self.number:
            info="Current Version: {} ".format(self.number)
            if verbose:
                info+="\n{}".format(super().get_infos(verbose)[0])
            return [info]
        else:
            return []

class WPItem(Finding):
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb"""
        if not data: data={}
        super().__init__(data)

        self.slug=data.get('slug', None)
        self.location=data.get('location', None)
        self.latest_version=data.get('latest_version', None)
        self.last_updated=data.get('last_updated', None)
        self.outdated=data.get('outdated', None)
        self.readme_url=data.get('readme_url', None)
        self.directory_listing=data.get('directory_listing', None)
        self.error_log_url=data.get('error_log_url', None) 
        self.version=WPItemVersion(data.get('version', None))

    def _get_warnings(self, verbose=False):
        """Return 0 or 1 warning. The warning can contain infos about oudated plugin, directory listing or accessible error log.
        First line of warning string is the plugin slug. Location also added as a reference."""
        # Test if there is issues
        issue_data=""
        if self.outdated: 
            issue_data+="\nWarning: The version is out of date\n"
        if self.directory_listing: 
            issue_data+="\nWarning: Directory listing is enabled\n"
        if self.error_log_url: 
            issue_data+="\nWarning: An error log file has been found: {}\n".format(self.error_log_url)

        if not issue_data: 
            return [] # Return if no issues
        else: 
            return [issue_data]

    def get_alerts(self, verbose=False):
        """Return list of know plugin or theme vulnerability. Empty list is returned if plugin version is unrecognized"""
        alerts=[]
        if self.version.get_infos(verbose):
            alerts.extend(["{}".format(warn) for warn in super().get_alerts(verbose)])
            alerts.extend(["{}".format(warn) for warn in self.version.get_alerts(verbose)])
        return alerts

    def get_warnings(self, verbose=False):
        """Return plugin or theme warnings, if oudated plugin, directory listing, accessible error log and 
        for all know vulnerabilities if plugin version could not be recognized.
        Adds a special warning saying the version is unrecognized if that's the case"""
        warnings=[]
        # Get oudated theme warning
        warning=self.slug
        if self._get_warnings(verbose):
            warning+=self._get_warnings(verbose)[0]
        # Get generic infos
        warning+=self._get_infos(verbose)[0]
        # If vulns are found and the version is unrecognized
        if not self.version.get_infos(verbose) and super().get_alerts(verbose):
            # Adds a special warning saying the version is unrecognized
            warning+="\nThe version could not be determined, all known vulnerabilities are listed.\nAdd vulnerabilities titles to false positves strings to ignore these messages."
        # If any issue
        if (not self.version.get_infos(verbose) and super().get_alerts(verbose)) or self._get_warnings(verbose):
            warnings.append(warning)
        # If potential vulns
        if not self.version.get_infos(verbose) and super().get_alerts(verbose):
            warnings.extend(["Potential {}".format(warn) for warn in super().get_alerts(verbose)])
            warnings.extend(["Potential {}".format(warn) for warn in self.version.get_alerts(verbose)])
        return warnings

    def _get_infos(self, verbose=False):
        """Return 1 info"""
        info=""
        if self.location: 
            info += "Location: {}".format(self.location)
        if self.latest_version:
            info += "\nLatest Version: {}".format(self.latest_version)
        if self.last_updated and verbose:
            info += "\nLast Updated: {}".format(self.last_updated)
        if self.readme_url:
            info += "\nReadme: {}".format(self.readme_url)
        info+="\n{}".format(super().get_infos(verbose)[0])
        if self.version.get_infos():
            info += "\n{}".format(self.version.get_infos(verbose)[0])
        else:
            info += "\nThe version could not be determined"
        
        return [info]
    
    def get_infos(self, verbose=False):
        """Return 0 or 1 info, no info if WPItem triggered warning, use get_warnings()"""
        if not self.get_warnings(verbose):
            return [ "{}\n{}".format(self.slug, self._get_infos(verbose)[0]) ]
        else:
            return []

class Plugin(WPItem):
    def __init__(self, data):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb"""
        if not data: data={}
        super().__init__(data)

    def get_infos(self, verbose=False):
        """Return 1 or 0 info if pluging trigerred warning"""
        return [ "Plugin: {}".format(info) for info in super().get_infos(verbose) ]

    def get_warnings(self, verbose=False):
        """Return plugin warnings"""
        # Adds plugin prefix on all warnings except vuln
        return [ "{}{}".format('Plugin: ' if 'Vulnerability' not in warning.splitlines()[0] else '', warning) 
            for warning in super().get_warnings(verbose) ]

class Theme(WPItem):
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb"""
        if not data: data={}
        super().__init__(data)

        self.style_url=data.get('style_url', None)
        self.style_name=data.get('style_name', None)
        self.style_uri=data.get('style_uri', None)
        self.description=data.get('description', None)
        self.author=data.get('author', None)
        self.author_uri=data.get('author_uri', None)
        self.template=data.get('template', None)
        self.license=data.get('license', None)
        self.license_uri=data.get('license_uri', None)
        self.tags=data.get('tags', None)
        self.text_domain=data.get('text_domain', None)
        self.parents=[Theme(theme) for theme in data.get('parents', [])]

    def _get_infos(self, verbose=False):
        """Return 1 info"""
        info=super()._get_infos(verbose)[0]

        if self.style_url:
            info+="\nStyle URL: {}".format(self.style_url)
        if self.style_name:
            info+="\nStyle Name: {}".format(self.style_name)
        if self.style_uri:
            info+="\nStyle URI: {}".format(self.style_uri)
        if self.description and verbose:
            info+="\nDescription: {}".format(self.description)
        if self.author:
            info+="\nAuthor: {}".format(self.author)
        if self.author_uri:
            info+="\nAuthor URI: {}".format(self.author_uri)
        if self.template and verbose:
            info+="\nTemplate: {}".format(self.template)
        if self.license and verbose:
            info+="\nLicense: {}".format(self.license)
        if self.license_uri and verbose:
            info+="\nLicense URI: {}".format(self.license_uri)
        if self.tags and verbose:
            info+="\nTags: {}".format(self.tags)
        if self.text_domain and verbose:
            info+="\nDomain: {}".format(self.text_domain)

        if self.parents and verbose:
            info+="\nParent Theme(s): {}".format(', '.join([p.slug for p in self.parents]))
        
        return [info]

    def get_infos(self, verbose=False):
        if super().get_infos(verbose):
            return ["Theme: {}".format(super().get_infos(verbose)[0])]
        else:
            return []

    def get_warnings(self, verbose=False):
        """Return theme warnings"""
        return [ "{}{}".format('Theme: ' if 'Vulnerability' not in warning.splitlines()[0] else '', warning) 
            for warning in super().get_warnings(verbose) ]

class MainTheme(Theme): 
    
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb"""
        if not data: data={}
        super().__init__(data)

    def get_infos(self, verbose=False):
        """Return 1 info"""
        return [ "Main Theme: {}".format(info) for info in super(Theme, self).get_infos(verbose) ]

    def get_warnings(self, verbose=False):
        """Return Main Theme warnings"""
        return [ "{}{}".format('Main Theme: ' if 'Vulnerability' not in warning.splitlines()[0] else '', warning) 
            for warning in super(Theme, self).get_warnings(verbose) ]

class Timthumb(Finding):
    
    def __init__(self, url, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb"""
        if not data: data={}
        super().__init__(data)
        self.url=url
        self.version=WPItemVersion(data.get('version', None))

    def get_infos(self, verbose=False):
        """Return 1 info"""
        info="Timthumb: {}\n{}".format(self.url, super().get_infos(verbose)[0])
        if self.version.get_infos():
                info += "\n{}".format(self.version.get_infos(verbose)[0])
        else:
            info += "\nThe version could not be determined"
        return [info]

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_alerts(self, verbose=False):
        """Return timthumb vulnerabilities"""
        return [ "Timthumb {}".format(alert) for alert in super().get_alerts(verbose)+ self.version.get_alerts(verbose) ]

class DBExport(Finding):
    
    def __init__(self, url, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb"""
        if not data: data={}
        super().__init__(data)
        self.url=url

    def get_alerts(self, verbose=False):
        """Return DBExport alerts"""
        alert="Database Export: {}\n{}".format(self.url, super().get_infos(verbose)[0])
        return [alert]
    
    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_infos(self, verbose=False):
        """Return empty list"""
        return []

class User(Finding):
    
    def __init__(self, username, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb
        And https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb
        """
        if not data: data={}
        super().__init__(data)
        
        self.username=username
        self.id=data.get('id', None)
        self.password=data.get('password', None)

    def get_infos(self, verbose=False):
        """Return 1 info"""
        info="User Identified: {}".format(self.username)
        info+="\n{}".format(super().get_infos(verbose)[0])
        return [info]

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_alerts(self, verbose=False):
        """Return 0 or 1 alert. Alert if password found"""
        if self.password:
            alert="Username: {}".format(self.username)
            alert+="Password: {}".format(self.password)
            return [alert]
        else:
            return []

class PasswordAttack(Component):
    
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb"""
        if not data: data={}
        super().__init__(data)

        self.users = [ User(user, data.get(user)) for user in data ] 

    def get_alerts(self, verbose=False):
        """Return Password Attack Valid Combinations Found alerts"""
        alerts=[]
        for user in self.users:
            alert="Password Attack Valid Combinations Found:"
            if user.get_alerts(verbose):
                alert+="\n{}".format(user.get_alerts(verbose)[0])
                alerts.append(alert)

        return alerts

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_infos(self, verbose=False):
        """Return empty list"""
        return []

class NotFullyConfigured(Component):

    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb"""
        if not data: data={}
        super().__init__(data)
        self.not_fully_configured=data
    
    def get_alerts(self, verbose=False):
        """Return 1 alert"""
        return ["Wordpress: {}".format(self.not_fully_configured)]
        
    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_infos(self, verbose=False):
        """Return empty list"""
        return []

class Media(Finding):

    def __init__(self, url, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb"""
        if not data: data={}
        super().__init__(data)
        self.url=url
    
    def get_infos(self, verbose=False):
        """Return 1 Media info"""
        alert="Media: {}".format(self.url)
        alert+="\n{}".format(super().get_infos(verbose)[0])
        return [alert]
    
    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_alerts(self, verbose=False):
        """Return empty list"""
        return []

class ConfigBackup(Finding):

    def __init__(self, url, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb"""
        if not data: data={}
        super().__init__(data)
        self.url=url

    def get_alerts(self, verbose=False):
        """Return 1 Config Backup alert"""
        alert="Config Backup: {}".format(self.url)
        alert+="\n{}".format(super().get_infos(verbose)[0])
        return [alert]
    
    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_infos(self, verbose=False):
        """Return empty list"""
        return []

class VulnAPI(Component):
    
    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb"""
        if not data: data={}
        super().__init__(data)
        
        self.http_error=data.get('http_error', None)
        self.error=data.get('error', None)

        self.plan=data.get('plan', None)
        self.requests_done_during_scan=data.get('requests_done_during_scan', None)
        self.requests_remaining=data.get('requests_remaining', None)

    def get_infos(self, verbose=False):
        """Return 1 WPVulnDB info"""
        info="WPVulnDB API Infos"
        info+="\nPlan: {}".format(self.plan)
        info+="\nRequests Done During Scan: {}".format(self.requests_done_during_scan)
        info+="\nRequests Remaining: {}".format(self.requests_remaining)
        return [info]
    
    def get_warnings(self, verbose=False):
        """Return 0 or 1 warning. VulnAPI error No WPVulnDB API Token given or HTTP errors"""
        warning=""
        if self.http_error:
            warning+="HTTP Error: {}".format(self.http_error)
        if self.error:
            warning+=self.error
        if warning:
            return [warning]
        else:
            return []

    def get_alerts(self, verbose=False):
        """Return empty list"""
        return []

class InterestingFinding(Finding):

    def __init__(self, data): 
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/interesting_findings/findings.erb"""
        if not data: data={}
        super().__init__(data)
        self.url=data.get('url', None)
        self.to_s=data.get('to_s', None)
        self.type=data.get('type', None)
        self.references=data.get('references', None)

    def get_infos(self, verbose=False):
        """Return 1 info. First line of info string is the to_s string or the finding type"""
        info=""
        if self.to_s != self.url:
            info+=self.to_s
        elif self.type:
            info+=self.type.title()
        if self.url:
            info+="\nURL: {}".format(self.url)
        info+="\n{}".format(super().get_infos(verbose)[0])
        if self.references: 
            info+='\nReferences: '
            for ref in self.references:
                for link in self.references[ref]:
                    info+="\n- {}: {}".format(ref.title(), link)

        return [info]

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_alerts(self, verbose=False):
        """Return empty list"""
        return []

class Banner(Component):

    def __init__(self, data): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb"""
        if not data: data={}
        super().__init__(data)

        self.description=data.get('description', None)
        self.version=data.get('version', None)
        self.authors=data.get('authors', None)
        self.sponsored_by=data.get('sponsored_by', None)

    def get_infos(self, verbose=False):
        info="Scanned with {}".format(self.description)
        info+='\nVersion: {}'.format(self.version)
        info+='\nAuthors: {}'.format(self.authors)
        info+='\nSponsored by: {}'.format(self.sponsored_by)

        return [info]

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_alerts(self, verbose=False):
        """Return empty list"""
        return []

class ScanStarted(Component):

    def __init__(self, data): 
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/started.erb"""
        if not data: data={}
        super().__init__(data)

        self.start_time=data.get('start_time', None)
        self.start_memory=data.get('start_memory', None)
        self.target_url=data.get('target_url', None)
        self.target_ip=data.get('target_ip', None)
        self.effective_url=data.get('effective_url', None)

    def get_infos(self, verbose=False):
        """Return 1 Scan Scanned info"""
        # info+='\nStart Time: {}'.format(self.start_time)
        # info+='\nStart Memory: {}'.format(self.start_memory)
        info='Target URL: {}'.format(self.target_url)
        info+='\nTarget IP: {}'.format(self.target_ip)
        info+='\nEffective URL: {}'.format(self.effective_url)

        return [info]

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_alerts(self, verbose=False):
        """Return empty list"""
        return []

class ScanFinished(Component):

    def __init__(self, data): 
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb"""
        if not data: data={}
        super().__init__(data)

        self.stop_time=data.get('stop_time', None)
        self.elapsed=data.get('elapsed', None)
        self.requests_done=data.get('requests_done', None)
        self.cached_requests=data.get('cached_requests', None)
        self.data_sent_humanised=data.get('data_sent_humanised', None)
        self.data_received_humanised=data.get('data_received_humanised', None)
        self.used_memory_humanised=data.get('used_memory_humanised', None)

    def get_infos(self, verbose=False):
        """Return 1 Scan Finished info"""
        # info+='\nStop Time: {}'.format(self.stop_time)
        info='Enlapsed: {} seconds'.format(self.elapsed)
        info+='\nRequests Done: {}'.format(self.requests_done)
        info+='\nCached Requests: {}'.format(self.cached_requests)
        info+='\nData Sent: {}'.format(self.data_sent_humanised)
        info+='\nData Received: {}'.format(self.data_received_humanised)
        info+='\nUsed Memory: {}'.format(self.used_memory_humanised)

        return [info]

    def get_warnings(self, verbose=False):
        """Return empty list"""
        return []

    def get_alerts(self, verbose=False):
        """Return empty list"""
        return []

########################  CLI PARSING ######################

def parse_cli_toogle(line, warning_on, alert_on):
    # Color parsing
    if "33m[!]" in line: warning_on=True
    elif "31m[!]" in line: alert_on = True
    # No color parsing Warnings string are hard coded here
    elif "[!]" in line and any([m in line for m in [   
        "The version is out of date",
        "No WPVulnDB API Token given",
        "You can get a free API token"]]) :
        warning_on = True
    elif "[!]" in line :
        alert_on = True
    # Both method with color and no color apply supplementary proccessing 
    # Warning for insecure Wordpress
    if 'Insecure' in line: 
        warning_on = True
    # Lower voice of Vulnerabilities found but not plugin version
    if 'The version could not be determined' in line and alert_on:
        alert_on = False  
        warning_on = True 
    return ((warning_on, alert_on))

def ignore_false_positives(infos, warnings, alerts, false_positives_strings):
        """Process false positives"""
        for alert in warnings+alerts:
            if is_false_positive(alert, false_positives_strings):
                try: alerts.remove(alert)
                except ValueError:
                    warnings.remove(alert)
                infos.append("[False positive]\n{}".format(alert))

        return infos, warnings, alerts

def is_false_positive(string, false_positives_strings):
    """False Positive Detection"""
    for fp_string in false_positives_strings:
        if fp_string in string:
            return True

def parse_cli(wpscan_output, false_positives_strings):
    if "[+]" not in wpscan_output: 
        raise ValueError("The file does not seem to be a WPScan CLI log.")
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    # Init messages toogles
    warning_on, alert_on = False, False
    message_lines=[] 
    current_message=""

    # Every blank ("") line will be considered as a message separator
    for line in wpscan_output.splitlines()+[""]:

        # Parse all output lines and build infos, warnings and alerts
        line=line.strip()
        
        # Parse line
        warning_on, alert_on = parse_cli_toogle(line, warning_on, alert_on)

        # Remove colorization anyway after parsing
        line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line)
        # Append line to message. Handle the begin of the message case
        message_lines.append(line)

        # Build message
        current_message='\n'.join([m for m in message_lines if m not in ["","|"]]).strip()

        # Message separator just a white line.
        # Only if the message if not empty. 
        if ( line.strip() not in [""] or current_message.strip() == "" ) : 
            continue

        # End of the message

        # Post process message to separate ALERTS into different messages of same status and add rest of the infos to warnings
        if (alert_on or warning_on) and any(s in current_message for s in ['vulnerabilities identified','vulnerability identified']) : 
            messages_separated=[]
            msg=[]
            for l in message_lines+["|"]:
                if l.strip() == "|":
                    messages_separated.append('\n'.join([ m for m in msg if m not in ["","|"]] ))
                    msg=[]
                msg.append(l)

            # Append Vulnerabilities messages to ALERTS and other infos in one message
            vulnerabilities = [ m for m in messages_separated if '| [!] Title' in m.splitlines()[0] ]

            # Add the plugin infos to warnings or false positive if every vulnerabilities are ignore
            plugin_infos='\n'.join([ m for m in messages_separated if '| [!] Title' not in m.splitlines()[0] ])
            
            if len([v for v in vulnerabilities if not is_false_positive(v, false_positives_strings)])>0:
                warnings.append(plugin_infos+"\nAll known vulnerabilities are listed. Add vulnerabilities titles to false positves strings to ignore these messages")
            else:
                messages.append("[False positive]\n"+plugin_infos)

            if alert_on: alerts.extend(vulnerabilities)
            elif warning_on: warnings.extend(vulnerabilities)

        elif warning_on: warnings.append(current_message)
        else: messages.append(current_message)
        message_lines=[]
        current_message=""
        # Reset Toogle Warning/Alert
        warning_on, alert_on = False, False

    return (ignore_false_positives( messages, warnings, alerts, false_positives_strings ))
