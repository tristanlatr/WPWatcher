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

ALERT=1
WARNING=2
INFO=3

class Component():
    def __init__(self, data): 
        self.data=data
    
    def get_infos(self):
        return []

    def get_warnings(self):
        return []

    def get_alerts(self):
        return []

    def get_all_messages(self):
        return(
            self.get_alerts(),
            self.get_warnings(),
            self.get_infos()
        )

    def __str__(self):
        return('\n'.join(list(self.get_all_messages())))
    
    def __repr__(self):
        return(json.dumps(self.data, indent=4))

class WPScanJsonParser(Component):
    def __init__(self, data, false_positives=None):
        Component.__init__(self, data)

        self.false_positives=false_positives
        self.components=[]

        # Add components to list

    def get_infos(self):
        infos=[]
        [ infos.extend(component.get_infos()) for component in self.components ]
        return infos

    def get_warnings(self):
        warnings=[]
        [ warnings.extend(component.get_warnings()) for component in self.components ]
        return warnings

    def get_alerts(self):
        alerts=[]
        [ alerts.extend(component.get_alerts()) for component in self.components ]
        return alerts

class Vulnerability(Component):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb
    def __init__(self, data): 
        Component.__init__(self, data)

        self.title=data.get('title', None)
        self.cvss=data.get('cvss', None)
        self.fixed_in=data.get('fixed_in', None)
        self.references=data.get('references', None)

    def get_alerts(self):
        alert=self.title
        if self.cvss: 
            alert+='\nCVSS: {cvss}'.format(cvss=self.cvss)
        if self.fixed_in: 
            alert+='\nFixed in: {fixed_in}'.format(fixed_in=self.fixed_in)
        else:
            alert+='\nNot yet fixed!'
        if self.references: 
            alert+='\nReferences: '
            for ref in self.references:
                if ref == 'cve':
                    for cve in self.references[ref]: 
                        alert+="\n- CVE: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{cve}".format(cve=cve)
                elif ref == 'wpvulndb': 
                    for wpvulndb in self.references[ref]:
                        alert+="\n- WPVulnDB: https://wpvulndb.com/vulnerabilities/%s"%(wpvulndb)
                else:
                    for link in self.references[ref]:
                        alert+="\n- {ref}: {link}".format(ref=ref.title(), link=link)
        return([alert])

class WPItem(Component):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb
    def __init__(self, data): 
        Component.__init__(self, data)

        self.slug=None
        self.location=None
        self.latest_version=None
        self.last_updated=None
        self.outdated=None
        self.readme_url=None
        self.directory_listing=None
        self.error_log_url=None 
    pass

class Finding(Component):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb
    def __init__(self, data): 
        Component.__init__(self, data)

        self.found_by=None
        self.confidence=None
        self.interesting_entries=None
        self.confirmed_by=None
        self.vulnerabilities=[Vulnerability(vuln) for vuln in data.get('vulnerabilities', [])]
    pass

class WPItemVersion(Finding):
    # From themes, plugins and timthumbs
    # https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb
    # https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb
    # https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb
    def __init__(self, data): 
        Finding.__init__(self, data)
        self.number=None
        self.confidence=None
    pass

class Plugin(Finding, WPItem):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb
    def __init__(self, data):
        Finding.__init__(self, data)
        WPItem.__init__(self, data)

        self.version=WPItemVersion(data.get('version', None))

class Theme(Finding, WPItem):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb
    def __init__(self, data): 
        Finding.__init__(self, data)
        WPItem.__init__(self, data)

        self.style_url=None
        self.style_name=None
        self.style_uri=None
        self.description=None
        self.author=None
        self.author_uri=None
        self.template=None
        self.license=None
        self.license_uri=None
        self.tags=None
        self.text_domain=None

        self.version=WPItemVersion(data.get('version', None))
        self.parents=None

class Timthumb(Finding):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb
    def __init__(self, data): 
        Finding.__init__(self, data)
        self.version=WPItemVersion(data.get('version', None))

class MainTheme(Theme): 
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb
    def __init__(self, data): 
        Theme.__init__(self, data)

class WPVersion(Finding):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb
    def __init__(self, data): 
        Finding.__init__(self, data)
        self.number=None
        self.release_date=None
        self.status=None
        pass

class DBExport(Finding):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb
    def __init__(self, data): 
        Finding.__init__(self, data)

class PasswordAttack(Component):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb
    def __init__(self, data): 
        Component.__init__(self, data)

        self.users=[User(data.get(user)) for user in data]

class NotFullyConfigured(Component):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb
    def __init__(self, data): 
        Component.__init__(self, data)

class Media(Finding):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb
    def __init__(self, data): 
        Finding.__init__(self, data)
        self.url=None

class ConfigBackup(Finding):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb   
    def __init__(self, data): 
        Finding.__init__(self, data)

class User(Finding):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb
    # And https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb

    def __init__(self, data): 
        Finding.__init__(self, data)
        self.id=None
        self.username=None
        self.password=None

class VulnAPI(Component):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb
    def __init__(self, data): 
        Component.__init__(self, data)

        self.http_error=None
        self.plan=None
        self.requests_done_during_scan=None
        self.requests_remaining=None
        self.error=None

class InterestingFinding(Finding):
    # From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/interesting_findings/findings.erb
    # interesting_findings
    def __init__(self, data): 
        Finding.__init__(self, data)
        self.url=None
        self.to_s=None
        self.type=None
        self.references=None

class Banner(Component):
    # From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb
    # banner
    def __init__(self, data): 
        Component.__init__(self, data)

        self.description=None

class ScanStarted(Component):
    # From https://github.com/wpscanteam/CMSScanner/blob/04f8dbb7b0ac503e7fb46739bb34f40202545cc8/app/views/json/core/started.erb

    def __init__(self, data): 
        Component.__init__(self, data)

        self.start_time=None
        self.start_memory=None
        self.target_url=None
        self.target_ip=None
        self.effective_url=None

class ScanFinished(Component):
    # From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb
    def __init__(self, data): 
        Component.__init__(self, data)

        self.stop_time=None
        self.elapsed=None
        self.requests_done=None
        self.cached_requests=None
        self.data_sent_humanised=None
        self.data_received_humanised=None
        self.used_memory_humanised=None

def parse_results(wpscan_output, false_positives=[]):
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    is_json=False
    try:
        data=json.loads(wpscan_output)
        is_json=True
    except ValueError: pass
    if is_json: (messages, warnings, alerts)=parse_json(data)
    else:  (messages, warnings, alerts)=parse_cli(wpscan_output, false_positives)
    return (ignore_false_positives( messages, warnings, alerts, false_positives))   

def ignore_false_positives(messages, warnings, alerts, false_positives):
    #Process false positives
    for alert in alerts+warnings:
        if is_false_positive(alert, false_positives):
            try: alerts.remove(alert)
            except ValueError: warnings.remove(alert)
            messages.append("[False positive]\n"+alert)
    return messages, warnings, alerts

# False Positive Detection
def is_false_positive(string, false_positives):
    for fp_string in false_positives:
        if fp_string in string:
            return True
    return False

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

def parse_cli(wpscan_output, false_positives):
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
            if alert_on: alerts.extend(vulnerabilities)
            elif warning_on: warnings.extend(vulnerabilities)

            # Add rest of the plugin infos to warnings or infos if every vulnerabilities are ignore
            plugin_infos='\n'.join([ m for m in messages_separated if '| [!] Title' not in m.splitlines()[0] ])
            
            if len([v for v in vulnerabilities if not is_false_positive(v, false_positives)])>0:
                warnings.append(plugin_infos)
            else:
                messages.append("[False positive]\n"+plugin_infos)

        elif warning_on: warnings.append(current_message)
        else: messages.append(current_message)
        message_lines=[]
        current_message=""
        # Reset Toogle Warning/Alert
        warning_on, alert_on = False, False

    return (( messages, warnings, alerts ))

######### JSON PARSING FROM HERE #########

def parse_json(data):
    infos, warnings, alerts=[],[],[]
    # Do a sanity check to confirm the data is ok
    if not data or not 'target_url' in data or not data['target_url']:
        raise ValueError("No data in wpscan JSON output (None) or no 'target_url' field present in the provided Json data. The scan might have failed, data: \n"+str(data))

    # warnings, alerts=parse_vulnerabilities_and_outdated(data)
    # infos.extend(parse_misc_infos(data))
    # warnings.extend(parse_misc_warnings(data))
    # alerts.extend(parse_misc_alerts(data))
    wp_warning = parse_warning_wordpress(data.get('version', None))
    if wp_warning: 
        warnings.append(wp_warning)

    main_theme_warning = parse_warning_theme_or_plugin(data.get('main_theme', None))
    if main_theme_warning: 
        warnings.append(main_theme_warning)

    for slug in data.get('plugins', {}):
        plugin_warning = parse_warning_theme_or_plugin(data.get('plugins').get(slug))
        if plugin_warning: 
            if not data.get('plugins').get(slug).get('version', None):
                plugin_warning+="\nThe version could not be determined, all known vulnerabilites are listed"
            warnings.append(plugin_warning)
    # WIP

    return (( infos, warnings, alerts ))

def parse_warning_wordpress(finding):
    if not finding: 
        return None
    if finding.get('status', None)=="insecure":
        fdata=""
        fdata+="Insecure WordPress version %s identified (released on %s)"%(finding['number'], finding['release_date'])
        fdata+=parse_confidence(finding)
    return fdata
    
    # if "interesting_entries" in finding:
    #         if len(finding["interesting_entries"]) > 0:
    #             findingData += "\nInteresting Entries: %s" % (", ".join(finding["interesting_entries"]))
    # if "found_by" in finding:
    #         findingData += "\nFound by: %s" % finding["found_by"]

def parse_warning_theme_or_plugin(finding):
    if not finding: 
        return None
    fdata=""
    if 'slug' in finding:
        fdata+="%s" % finding['slug']
    # Test if there is issues
    issue_data=""
    if finding.get('outdated', None): 
        issue_data+="\nThe version is out of date, the latest version is %s" % (finding["latest_version"])
    if finding.get('directory_listing', None): 
        issue_data+="\nDirectory listing is enabled"
    if finding.get('error_log_url', None): 
        issue_data+="\nAn error log file has been found: %s" % (finding["error_log_url"])

    if not issue_data: 
        return None # Return if no issues
    else: 
        fdata+=issue_data

    if "location" in finding: 
        fdata += "\nLocation: %s" % finding["location"]

    # if "found_by" in finding:
    #     fdata += "\nFound by: %s" % finding["found_by"]

    fdata+=parse_confidence(finding)
    # fdata+=parse_interesting_entries(finding)
    return(fdata)



def parse_vulnerability(finding):
    # Finding can be a vulnerability or other
    findingData = ""
    refData = ""
    title=""
    # title = "%s:"%(finding_type) if finding_type else ""

    # if type(finding) is not dict: 
    #     raise TypeError("Must be a dict, method parse_a_finding() for data {}".format(finding)) 

    # For interesting findings
    # if "type" in finding: title += "%s\n" % finding["type"]
    # if "to_s" in finding: title += "%s" % finding["to_s"]
    # For vulnerabilities
    if "title" in finding: title += "%s" % finding["title"]
    findingData += "%s" % title
    if "fixed_in" in finding: findingData += "\nFixed In: %s" % finding["fixed_in"]
    # if "url" in finding: findingData += "\nURL: %s" % finding["url"]
    # findingData+=parse_confidence(finding)
    # findingData+=parse_interesting_entries(finding)
    refData=parse_references(finding)

    # if "comfirmed_by" in finding:
    #     if len(finding["confirmed_by"]) > 0:
    #         findingData += "\nConfirmed By:\n"
    #         findingData+="\n- ".join(finding["confirmed_by"])
    # if "found_by" in finding:
    #     findingData += "\nFound by: %s" % finding["found_by"]

    return ("%s %s" % (findingData, refData) )

######## END RE WRITE ########


def check_valid_section(data, section):
    if section in data and ( data[section] is not None or len(data[section])>0 ) : return True
    else: return False

def parse_slugs_vulnerabilities(node):
    warnings, alerts=[],[]
    if not node: return ((warnings, alerts))
    for slug in node:
        try: alerts.extend(parse_findings(node[slug]['vulnerabilities']))
        except KeyError: pass
        try: warnings.extend(parse_warning_theme_or_plugin(node[slug]))
        except KeyError: pass
    return ((warnings, alerts))

def parse_section_alerts(section, node):
    warnings, alerts=[],[]
    if not node: return ((warnings, alerts))
    if section=='version':
        warnings.extend(parse_warning_wordpress(node))
    if section=='main_theme':
        warnings.extend(parse_warning_theme_or_plugin(node))
    if any ([section==c for c in ['main_theme','version']]):
        try: alerts.extend(parse_findings(node['vulnerabilities']))
        except KeyError: pass
    warnings_alt,alerts_alt=[],[]
    if any([section==c for c in ['themes', 'plugins', 'timthumbs']]):
        warnings_alt, alerts_alt=parse_slugs_vulnerabilities(node)
        warnings.extend(warnings_alt)
        alerts.extend(alerts_alt)
    return ((warnings, alerts))

def parse_vulnerabilities_and_outdated(data):
    warnings, alerts=[],[]
    for section in data:
        warnings_sec, alerts_sec = parse_section_alerts(section, data[section])
        alerts.extend(alerts_sec)
        warnings.extend(warnings_sec)
    return ((warnings, alerts))

def wrap_parse_finding(data, section):
    alerts=[]
    if check_valid_section(data, section) :
        alerts.extend(parse_vulnerability_or_finding(data[section]))
    return alerts

def wrap_parse_simple_values(data, section, title):
    alerts=[]
    if check_valid_section(data, section) :
        for val in data[section]:
            alerts.append("%s%s"%(title, str(val)))
    return alerts

def parse_misc_alerts(data):
    return ( wrap_parse_simple_values(data, 'config_backups', 'WordPress Configuration Backup Found: ') + 
        wrap_parse_finding(data, 'db_exports')+ 
        wrap_parse_simple_values(data, 'password_attack', 'WordPres Weak User Password Found: ')+
        wrap_parse_finding(data, 'not_fully_configured') )

def parse_misc_warnings(data):
    warnings=wrap_parse_finding(data, 'medias')
    if check_valid_section(data, 'vuln_api') and 'error' in data['vuln_api']:
            warnings.append(data['vuln_api']['error'])
    return warnings

def parse_banner(data):
    if not check_valid_section(data, 'banner') : return []
    return wrap_parse_simple_values(data['banner'], 'version', 'Scanned with WPScan version: ')

def parse_target(data):
    messages=[]
    messages.append("Target URL: {}\nIP: {}\nEffective URL: {}".format(
        data['target_url'],
        data["target_ip"] if 'target_ip' in data else '?',
        data["effective_url"]))
    return messages

def parse_misc_infos(data):
    messages=parse_target(data)
    messages.extend(parse_banner(data))
    if check_valid_section(data, 'interesting_findings') :
        # Parse informations
        messages.extend(parse_findings(data["interesting_findings"]) )
    messages.extend(wrap_parse_simple_values(data, 'users', 'WordPress user found: '))
    return (messages)

def parse_interesting_entries(finding):
    fdata=""
    if check_valid_section(finding, 'interesting_entries') :
        fdata += "\nInteresting Entries: %s" % (", ".join(finding["interesting_entries"]))
    return fdata

def parse_confidence(finding):
    fdata=""
    if "confidence" in finding:
            fdata += "\nConfidence: %s" % finding["confidence"]
    return fdata

# Wrapper to parse findings can take list or dict type
def parse_findings(findings):
    summary = []
    if type(findings) is list:
        for finding in findings:
            summary.append(parse_vulnerability_or_finding(finding))
    elif type(findings) is dict:
        for finding in findings:
            summary.append(parse_vulnerability_or_finding(findings[finding]))
    else: raise TypeError("Must be a list or dict, method parse_findings() for data: {}".format(findings)) 
    return(summary)

# def parse_version_info(version):
#     headerInfo = ""

#     if "number" in version:
#         headerInfo += "Running WordPress version: %s\n" % version["number"]

#     if "interesting_entries" in version:
#             if len(version["interesting_entries"]) > 0:
#                 headerInfo += "\nInteresting Entries: %s" % (", ".join(version["interesting_entries"]))

#     return headerInfo