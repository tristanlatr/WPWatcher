#! /usr/bin/env python3
# 
# WPScan output parser
# 
# Authors: Florian Roth, Tristan Landès
#
# DISCLAIMER - USE AT YOUR OWN RISK.
# 
# Some infos are intentionally ignored when parsing Json to have shorter output.
# You can use --format cli to show all informations with Infos, Warnings and Alerts
# 
# Exemple stdin usage:
#   $ wpscan --url https://exemple.com --format json | python3 ./parser.py
#
# With param --input :
#   $ python3 ./parser.py --input wpscan.log
#
# Or you can import this package into your application and call `parse_results` method.
#   from wpwatcher.parser import parse_results
#   (messages, warnings, alerts) = parse_results(wpscan_output_string)

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
    for alert in alerts:
        if is_false_positive(alert, false_positives):
            alerts.remove(alert)
            messages.append("[False positive]\n"+alert)

    for warn in warnings:
        if is_false_positive(warn, false_positives):
            warnings.remove(warn)
            messages.append("[False positive]\n"+warn)
    
    return (( messages, warnings, alerts ))

def parse_cli(wpscan_output):
    if "[+]" in wpscan_output:
        # Init scan messages
        ( messages, warnings, alerts ) = ([],[],[])
        # Init messages toogles
        warning_on = False
        alert_on = False
        # Test if cli_with_colors
        cli_with_colors= ( "32m[+]" in wpscan_output )
        message="" 
        # Every blank ("") line will be considered as a message separator
        for line in wpscan_output.splitlines():

            # Parse all output lines and build infos, warnings and alerts
            line=line.strip()

            # Empty content lines are ignored
            # Parse the line and Toogle Warning/Alert
            if line!="" and line!="|":   

                # Toogle Warning/Alert if specific match in any line of the message
                if cli_with_colors==False:

                    # Method 1 : No color. Warnings string are hard coded here -------------
                    # Remove colorization
                    # line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line)
                    if "[!]" in line and any([m in line for m in [   
                        "The version is out of date",
                        "No WPVulnDB API Token given",
                        "You can get a free API token"]]) :
                        warning_on = True
                    elif "[!]" in line :
                        alert_on = True

                    # Method 2 : Cli with colors parsing ------------------------------------
                else: 
                    if "33m[!]" in line: warning_on=True
                    if "31m[!]" in line: alert_on = True
                    # Remove colorization anyway after parsing
                    line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line)

                # Both method with color and no color apply supplementary proccessing 
                # Warning for insecure Wordpress
                if 'Insecure' in line: 
                    warning_on = True
                # Lower voice of Vulnerabilities found but not plugin version
                if 'The version could not be determined' in line and alert_on:
                        alert_on = False  
                        warning_on = True 

                # When line message has been read and parsed
                # Append line to message. Handle the begin of the message case
                message+= line if message=="" else '\n'+line 

            # Message separator just a white line.
            elif line=="":
                # Only if the message if not empty. 
                # End of the message
                if message.strip() != "":
                    # Append messages to list of infos, warns and alerts
                    if alert_on: alerts.append(message)
                    elif warning_on: warnings.append(message)
                    else: messages.append(message)
                    message=""
                    # Reset Toogle Warning/Alert
                    alert_on = False  
                    warning_on = False

        # Catching last message after loop
        if alert_on: alerts.append(message)
        elif warning_on: warnings.append(message)
        else: messages.append(message)
        return (( messages, warnings, alerts ))
    else: 
        raise Exception("The file does not seem to be a WPScan CLI log.")

def parse_vulnerabilities_and_warnings_only(data):
    alerts=[]
    warnings=[]
    for section in data:
        node=data[section]
        if section=='version':
            warnings.extend(parse_warning_wordpress(node))
        if section=='main_theme':
            warnings.extend(parse_warning_theme_or_plugin(node))
        if any ([section==c for c in ['main_theme','version']]):
            try: alerts.extend(parse_findings(node['vulnerabilities']))
            except: pass
        if any([section==c for c in ['themes', 'plugins', 'timthumbs']]):
            for slug in node:
                try: alerts.extend(parse_findings(node[slug]['vulnerabilities']))
                except: pass
                try: warnings.extend(parse_warning_theme_or_plugin(node[slug]))
                except: pass
    return ((warnings, alerts))

def parse_json(data):
    # Do a sanity check to confirm the data is ok
    if data and 'target_url' in data and data['target_url']:
        warnings, alerts=parse_vulnerabilities_and_warnings_only(data)
        infos, w1, a1=parse_other_infos(data)
        warnings.extend(w1)
        alerts.extend(a1)
        return (( infos, warnings, alerts ))
    else: 
        raise Exception("No data in wpscan Json output (None) or no 'target_url' field present in the provided Json data. The scan might have failed, data: \n"+str(data))
    
def parse_other_infos(data):
    messages=[]
    warnings=[]
    alerts=[]
    messages.append("Target URL: {}\nIP: {}\nEffective URL: {}".format(
        data['target_url'],
        data["target_ip"],
        data["effective_url"]))
    
    if "banner" in data:
        messages.append("Scanned with WPScan version {}".format(data['banner']['version']))

    if "last_db_update" in data:
        messages.append("Last WPScan database update: {}".format(data['last_db_update']))

    # Parse know vulnerabilities
    # Parse vulnerability data and make more human readable.
    # NOTE: You need an API token for the WPVulnDB vulnerability data.

    if "interesting_findings" in data:
        if data["interesting_findings"] is not None and len(data["interesting_findings"])>0:
            # Parse informations
            messages.extend(parse_findings(data["interesting_findings"]) )

    if "users" in data:
        if data["users"] is not None and len(data["users"])>0:
            users = data["users"]
            for name in users:
                # Parse users
                messages.append( 'WordPress user found: %s'%name )
    
    if "config_backups" in data:
        if data["config_backups"] is not None or len(data["config_backups"])>0:
            for url in data['config_backups']:
                alerts.append("WordPress Configuration Backup Found\nURL: %s"%str(url) )

    if "db_exports" in data :
        if data['db_exports'] is not None and len(data['db_exports'])>0:
            alerts.extend(parse_vulnerability_or_finding(data['db_exports'] ))

    if "password_attack" in data :
        if data['password_attack'] is not None and len(data['password_attack'])>0:
            for passwd in data['password_attack']:
                alerts.append("WordPres Weak User Password Found:\n%s"%str(passwd) )

    if "medias" in data :
        if data['medias'] is not None and len(data['medias'])>0:
            warnings.extend(parse_vulnerability_or_finding(data['medias']))

    if "vuln_api" in data :
        if "error" in data['vuln_api']:
            warnings.append(data['vuln_api']["error"])

    if "not_fully_configured" in data and data['not_fully_configured']!=None :
        alerts.append(data['not_fully_configured'])

    return (( messages, warnings, alerts ))

    # Older code not ised anymore

    # if "main_theme" in data:
    #     if data["main_theme"]==None or len(data["main_theme"])==0:
    #         messages.append("WPScan did not find any main theme information")
    #     else:
    #         # Parse theme warnings
    #         warnings.extend(parse_warning_theme_or_plugin('main theme',data['main_theme']) )

    #         if "vulnerabilities" in data["main_theme"]:
    #             # Parse Vulnerable themes
    #             alerts.extend(parse_findings('Vulnerable theme',data["main_theme"]["vulnerabilities"]) )

    #         if "version" in data["main_theme"] and data["main_theme"]["version"] != None and "vulnerabilities" in data["main_theme"]["version"] :
    #             # Parse vulnerable theme version
    #             alerts.extend(parse_findings('Vulnerable theme',data["main_theme"]["version"]["vulnerabilities"]) )
    
    # if "version" in data:
    #     if data["version"]==None or len(data["version"])==0:
    #         messages.append("WPScan did not find any WordPress version")
    #     else:
    #         # Parse WordPress version
    #         messages.append(parse_version_info(data['version']))
    #         # Parse outdated WordPress version
    #         warnings.extend(parse_warning_wordpress(data['version']) )
    #         # Parse vulnerable WordPress version
    #         alerts.extend(parse_findings('Vulnerable wordpress',data["version"]["vulnerabilities"]) )
    
    # if "themes" in data:
    #     if data["themes"]==None or len(data["themes"])==0:
    #         messages.append("WPScan did not find any theme information")
    #     else:
    #         for theme in data["themes"]:
    #             # Parse secondary theme warnings
    #             warnings.extend(parse_warning_theme_or_plugin('theme',theme) )
    #             # Parse secondary Vulnerable themes
    #             alerts.extend(parse_findings('Vulnerable theme', data["themes"][theme]["vulnerabilities"]) )
    
    # if "plugins" in data:
    #     if data["plugins"]==None or len(data["plugins"])==0:
    #         messages.append("WPScan did not find any WordPress plugins")
    #     else:
    #         plugins = data["plugins"]
    #         for plugin in plugins:
    #             # Parse vulnerable plugins
    #             alerts.extend(parse_findings('Vulnerable pulgin',plugins[plugin]["vulnerabilities"]) )
    #             # Parse outdated plugins
    #             warnings.extend(parse_warning_theme_or_plugin('plugin',plugins[plugin]) )

def parse_vulnerability_or_finding(finding):
    # Finding can be a vulnerability or other
    findingData = ""
    refData = ""
    title=""
    # title = "%s:"%(finding_type) if finding_type else ""

    if type(finding) is dict:
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

        if "confidence" in finding:
            findingData += "\nConfidence: %s" % finding["confidence"]

        if "interesting_entries" in finding:
            if len(finding["interesting_entries"]) > 0:
                findingData += "\nInteresting Entries: %s" % (", ".join(finding["interesting_entries"]))

        # if "comfirmed_by" in finding:
        #     if len(finding["confirmed_by"]) > 0:
        #         findingData += "\nConfirmed By:\n"
        #         findingData+="\n- ".join(finding["confirmed_by"])

        if "references" in finding and len(finding["references"]) > 0:
            refData += "\nReferences:"
            for ref in finding["references"]:
                if ref =='cve':
                    for cve in finding["references"][ref]: refData+="\n- CVE: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-%s"%(cve)
                elif ref == 'wpvulndb': 
                    for wpvulndb in finding["references"][ref]: refData+="\n- wpvulndb: https://wpvulndb.com/vulnerabilities/%s"%(wpvulndb)
                else:
                    refData += "\n- %s: %s" % (ref, ", ".join(finding["references"][ref]) )

    else: raise TypeError("Must be a dict, method parse_a_finding() for data {}".format(finding)) 
    return ("%s %s" % (findingData, refData) )

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

    if "confidence" in finding:
        findingData += "\nConfidence: %s" % finding["confidence"]

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

    if "confidence" in finding:
        findingData += "\nConfidence: %s" % finding["confidence"]

    if "interesting_entries" in finding:
        if len(finding["interesting_entries"]) > 0:
            findingData += "\nInteresting Entries: %s" % (", ".join(finding["interesting_entries"]))

    if warn: summary.append(findingData)
    return(summary)

# False Positive Detection
def is_false_positive(string, false_positives):
    for fp_string in false_positives:
        if fp_string in string:
            return True
    return False

def parse_args():
    parser = argparse.ArgumentParser(description='WPscan output parser')
    parser.add_argument('--input', '-i', metavar='path', help="WPScan Json or CLI output")
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    args=parse_args()
    if args.input:
        # Parse file
        with open(args.input) as wpout:
            (infos, warnings, alerts)=parse_results( wpout.read() , [] )
    else:
        # Parse stdin
        lines = sys.stdin.readlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace('\n','')
        (infos, warnings, alerts)=parse_results( '\n'.join(lines) , [] )
        
    # Building message
    if (warnings or alerts) :message = "Issues have been detected by WPScan.\n"
    else: message = "WPScan report\n"
    if alerts:
        message += "\n\n\tAlerts\n\n"
        message += "\n\n".join(alerts)
    if warnings:
        message += "\n\n\tWarnings\n\n"
        message += "\n\n".join(warnings)
    if infos:
        message += "\n\n\tInformations\n\n"
        message += "\n\n".join(infos)
    print(message)
