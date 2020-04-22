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
import sys
import argparse

def parse_results(wpscan_output, false_positives=[]):
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    is_json=False
    try:
        data=json.loads(wpscan_output)
        is_json=True
    except: pass
    if is_json:
        (messages, warnings, alerts)=parse_json(data)
    else: 
        (messages, warnings, alerts)=parse_cli(wpscan_output)
    #Process false positives
    for alert in alerts+warnings:
        if is_false_positive(alert, false_positives):
            try: alerts.remove(alert)
            except ValueError: warnings.remove(alert)
            messages.append("[False positive]\n"+alert)

    # for warn in warnings:
    #     if is_false_positive(warn, false_positives):
    #         warnings.remove(warn)
    #         messages.append("[False positive]\n"+warn)
    
    return (( messages, warnings, alerts ))   

def parse_cli_toogle(line):
    warning_on, alert_on = False, False
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

def parse_cli(wpscan_output):
    if "[+]" not in wpscan_output: raise Exception("The file does not seem to be a WPScan CLI log.")
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    # Init messages toogles
    warning_on, alert_on = False, False
    message_lines=[] 
    # Every blank ("") line will be considered as a message separator
    for line in wpscan_output.splitlines()+[""]:

        # Parse all output lines and build infos, warnings and alerts
        line=line.strip()
        current_message='\n'.join(message_lines).strip()
        # Empty content lines are ignored
        # Parse the line and Toogle Warning/Alert
        if line not in ["","|"] :   
            # Toogle Warning/Alert if specific match in any line of the message
             # Both method with color and no color apply supplementary proccessing 
            warning_on_alt,alert_on_alt=parse_cli_toogle(line)
            warning_on, alert_on = warning_on or warning_on_alt, alert_on or alert_on_alt
            # When line message has been read and parsed
            # Remove colorization anyway after parsing
            line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line)
            # Append line to message. Handle the begin of the message case
            message_lines.append(line) #+= line if message=="" else '\n'+line 

        # Message separator just a white line.
        # Only if the message if not empty. 
        if not ( line=="" and current_message != "" ) : break

        # End of the message
        # Append messages to list of infos, warns and alerts
        if alert_on: alerts.append(current_message)
        elif warning_on: warnings.append(current_message)
        else: messages.append(current_message)
        message_lines=[]
        # Reset Toogle Warning/Alert
        alert_on = False  
        warning_on = False

    return (( messages, warnings, alerts ))

######### JSON PARSING FROM HERE #########

def parse_json(data):
    infos, warnings, alerts=[],[],[]
    # Do a sanity check to confirm the data is ok
    if data and 'target_url' in data and data['target_url']:
        warnings, alerts=parse_vulnerabilities_and_outdated(data)
        infos.extend(parse_misc_infos(data))
        warnings.extend(parse_misc_warnings(data))
        alerts.extend(parse_misc_alerts(data))
        return (( infos, warnings, alerts ))
    else: 
        raise Exception("No data in wpscan Json output (None) or no 'target_url' field present in the provided Json data. The scan might have failed, data: \n"+str(data))

def check_valid_section(data, section):
    if section in data and ( data[section] is not None or len(data[section])>0 ) : return True
    else: return False

def parse_slugs_vulnerabilities(node):
    warnings, alerts=[],[]
    for slug in node:
            try: alerts.extend(parse_findings(node[slug]['vulnerabilities']))
            except: pass
            try: warnings.extend(parse_warning_theme_or_plugin(node[slug]))
            except: pass
    return ((warnings, alerts))

def parse_section_alerts(section, node):
    warnings, alerts=[],[]
    if section=='version':
        warnings.extend(parse_warning_wordpress(node))
    if section=='main_theme':
        warnings.extend(parse_warning_theme_or_plugin(node))
    if any ([section==c for c in ['main_theme','version']]):
        try: alerts.extend(parse_findings(node['vulnerabilities']))
        except: pass
    if any([section==c for c in ['themes', 'plugins', 'timthumbs']]):
        warnings_alt, alerts_alt=parse_slugs_vulnerabilities(node)
    return ((warnings.extend(warnings_alt), alerts.extend(alerts_alt)))

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

# def parse_config_backups(data):
#     return wrap_parse_simple_values(data, 'config_backups', 'WordPress Configuration Backup Found: ')

# def parse_db_exports(data):
#     return wrap_parse_finding(data, 'db_exports')

# def parse_password_attack(data):
#     return wrap_parse_simple_values(data, 'password_attack', 'WordPres Weak User Password Found: ')

# def parse_not_fully_configured(data):
#     return wrap_parse_finding(data, 'not_fully_configured')

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

def parse_vulnerability_or_finding(finding):
    # Finding can be a vulnerability or other
    findingData = ""
    refData = ""
    title=""
    # title = "%s:"%(finding_type) if finding_type else ""

    if type(finding) is not dict: raise TypeError("Must be a dict, method parse_a_finding() for data {}".format(finding)) 

    # For interesting findings
    # if "type" in finding:
    #     title += "[%s]" % finding["type"]
    if "to_s" in finding:
        title += "%s" % finding["to_s"]

    # For vulnerabilities
    if "title" in finding:
        title += "%s" % finding["title"]

    findingData += "%s" % title

    if "fixed_in" in finding:
        findingData += "\nFixed In: %s" % finding["fixed_in"]

    if "url" in finding:
        findingData += "\nURL: %s" % finding["url"]

    # if "found_by" in finding:
    #     findingData += "\nFound by: %s" % finding["found_by"]

    findingData+=parse_confidence(finding)

    findingData+=parse_interesting_entries(finding)

    refData=parse_references(finding)

    # if "comfirmed_by" in finding:
    #     if len(finding["confirmed_by"]) > 0:
    #         findingData += "\nConfirmed By:\n"
    #         findingData+="\n- ".join(finding["confirmed_by"])c

    return ("%s %s" % (findingData, refData) )

def parse_references(finding):
    refData = ""
    if not check_valid_section(finding, 'references'):
        return refData
    refData += "\nReferences:"
    for ref in finding["references"]:
        refData+=parse_ref(finding, ref)
    return refData

def parse_ref(finding, ref):
    refData=""
    if ref =='cve':
        for cve in finding["references"][ref]: refData+="\n- CVE: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-%s"%(cve)
    elif ref == 'wpvulndb': 
        for wpvulndb in finding["references"][ref]: refData+="\n- wpvulndb: https://wpvulndb.com/vulnerabilities/%s"%(wpvulndb)
    else:
        refData += "\n- %s: %s" % (ref, ", ".join(finding["references"][ref]) )
    return refData

# Wrapper to parse findings can take list or dict type
def parse_findings(findings):
    summary = []
    if type(findings) is list:
        for finding in findings:
            summary.append(parse_vulnerability_or_finding(finding))
    elif type(findings) is dict:
        for finding in findings:
            summary.append(parse_vulnerability_or_finding(findings[finding]))
    else:
        raise TypeError("Must be a list or dict, method parse_findings() for data: {}".format(findings)) 
    return(summary)

# def parse_version_info(version):
#     headerInfo = ""

#     if "number" in version:
#         headerInfo += "Running WordPress version: %s\n" % version["number"]

#     if "interesting_entries" in version:
#             if len(version["interesting_entries"]) > 0:
#                 headerInfo += "\nInteresting Entries: %s" % (", ".join(version["interesting_entries"]))

#     return headerInfo

def parse_warning_wordpress(finding):
    summary=[]
    if not finding: return summary
    warn=False
    findingData=""

    if 'status' in finding and finding['status']=="insecure":
        findingData+="Insecure WordPress version %s identified (released on %s)"%(finding['number'], finding['release_date'])
        warn=True

    # if "found_by" in finding:
    #         findingData += "\nFound by: %s" % finding["found_by"]

    findingData+=parse_confidence(finding)

    # if "interesting_entries" in finding:
    #         if len(finding["interesting_entries"]) > 0:
    #             findingData += "\nInteresting Entries: %s" % (", ".join(finding["interesting_entries"]))

    if warn: summary.append(findingData)
    return(summary)

def parse_warning_theme_or_plugin(finding):
    summary=[]
    if not finding: return summary
    warn=False
    findingData=""

    if 'slug' in finding:
        findingData+="%s" % finding['slug']

    if 'outdated' in finding and finding['outdated']==True:
        findingData+="\nThe version is out of date, the latest version is %s" % (finding["latest_version"])
        warn=True

    if "directory_listing" in finding and finding['directory_listing']:
        findingData+="\nDirectory listing is enabled"
        warn=True

    if "error_log_url" in finding and finding['error_log_url']:
        findingData+="\nAn error log file has been found: %s" % (finding["error_log_url"])
        warn=True

    if "location" in finding:
        findingData += "\nLocation: %s" % finding["location"]

    # if "found_by" in finding:
    #     findingData += "\nFound by: %s" % finding["found_by"]

    findingData+=parse_confidence(finding)

    findingData+=parse_interesting_entries(finding)

    if warn: summary.append(findingData)
    return(summary)

# False Positive Detection
def is_false_positive(string, false_positives):
    for fp_string in false_positives:
        if fp_string in string:
            return True
    return False