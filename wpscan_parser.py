#! /usr/bin/env python3
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# WPScan output parser
# DISCLAIMER - USE AT YOUR OWN RISK.

import json
import re
import sys
import argparse

# Parsing the wpscan_output
# Can be used like 
#   $ wpscan --url https://exemple.com --format json | python3 ./wpscan_parser.py
#   Or --format cli . 
#
#   With param --input :
#   $ python3 ./wpscan_parser.py --input wpscan.log
# Parse and return ( messages, warnings, alerts )

"""
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
"""
def parse_json(wpscan_output):
     # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])

    try :
        data=json.loads(wpscan_output)
        # Do a sanity check to confirm the data is ok
        if data and 'target_url' in data and data['target_url']:

            messages.append("Target URL: {}\nIP: {}\n Effective URL: {}".format(
                data['target_url'],
                data["target_ip"],
                data["effective_url"]))
            
            if "banner" in data:
                messages.append("Scanned with WPScan version {}".format(data['banner']['version']))

            # Parse know vulnerabilities
            # Parse vulnerability data and make more human readable.
            # NOTE: You need an API token for the WPVulnDB vulnerability data.


            if "interesting_findings" in data:
                if data["interesting_findings"]==None:
                    messages.append("WPScan did not find any interesting informations")
                else:
                    # Parse informations
                    messages.extend(parse_findings('Interesting findings', data["interesting_findings"]) )
            
            if "main_theme" in data:
                if data["main_theme"]==None:
                    messages.append("WPScan did not find any main theme information")
                else:
                    # Parse theme warnings
                    warnings.extend(parse_warning_theme_or_plugin('main theme',data['main_theme']) )

                    if "vulnerabilities" in data["main_theme"]:
                        # Parse Vulnerable themes
                        alerts.extend(parse_findings('Vulnerable theme',data["main_theme"]["vulnerabilities"]) )

                    if "version" in data["main_theme"] and data["main_theme"]["version"] != None and "vulnerabilities" in data["main_theme"]["version"] :
                        # Parse vulnerable theme version
                        alerts.extend(parse_findings('Vulnerable theme',data["main_theme"]["version"]["vulnerabilities"]) )
            
            if "version" in data:
                if data["version"]==None:
                    messages.append("WPScan did not find any WordPress version")
                else:
                    # Parse WordPress version
                    messages.append(parse_version_info(data['version']))
                    # Parse outdated WordPress version
                    warnings.extend(parse_warning_wordpress(data['version']) )
                    # Parse vulnerable WordPress version
                    alerts.extend(parse_findings('Vulnerable wordpress',data["version"]["vulnerabilities"]) )
            
            if "themes" in data:
                if data["themes"]==None:
                    messages.append("WPScan did not find any theme information")
                else:
                    for theme in data["themes"]:
                        # Parse secondary theme warnings
                        warnings.extend(parse_warning_theme_or_plugin('theme',theme) )
                        # Parse secondary Vulnerable themes
                        alerts.extend(parse_findings('Vulnerable theme',theme["vulnerabilities"]) )
            
            if "plugins" in data:
                if data["plugins"]==None:
                    messages.append("WPScan did not find any WordPress plugins")
                else:
                    plugins = data["plugins"]
                    for plugin in plugins:
                        # Parse vulnerable plugins
                        alerts.extend(parse_findings('Vulnerable pulgin',plugins[plugin]["vulnerabilities"]) )
                        # Parse outdated plugins
                        warnings.extend(parse_warning_theme_or_plugin('plugin',plugins[plugin]) )

            if "users" in data:
                if data["users"]==None:
                    messages.append("WPScan did not find any WordPress users")
                else:
                    users = data["users"]
                    for name in users:
                        # Parse users users
                        warnings.append( parse_a_finding('User found: %s'%name,users[name]) )
            
            if "config_backups" in data:
                if data["config_backups"]==None:
                    messages.append("WPScan did not find any WordPress config backups")
                else:
                    for url in data['config_backups']:
                        alerts.append("WordPress Configuration Backup Found\nURL: %s"%str(url) )

            if "db_exports" in data :
                if data['db_exports']==None:
                    messages.append("WPScan did not find any WordPress db exports")
                else:
                    for db in data['db_exports']:
                        alerts.append("WordPress Database Export Found\nURL: %s"%str(db) )

            if "timthumbs" in data :
                if data['timthumbs']==None:
                    messages.append("WPScan did not find any WordPress timthumbs")
                else:
                    for tt in data['timthumbs']:
                        alerts.extend(parse_findings("WordPress timthumbs Vulnerability\nURL: %s"%url, data['timthumbs'][tt]["vulnerabilities"]) )
                        messages.extend(parse_findings("WordPress timthumbs \nURL: %s"%url, data['timthumbs'][tt]) )

            if "password_attack" in data :
                if data['password_attack']==None:
                    messages.append("WPScan did not find any login / password")
                else:
                    for passwd in data['password_attack']:
                        alerts.append("WordPres Weak User Password Found:\n%s"%str(passwd) )

        else: 
            raise Exception("No data in wpscan Json output (None) or no 'target_url' field present in the provided Json data. The scan might have failed, ouput: \n"+wpscan_output)
    
    except Exception as err:
        # Default parsing is json, if fails will try cli
        if "[+]" in wpscan_output:
            try:
                (messages, warnings, alerts)=parse_cli(wpscan_output)
            except:
                raise Exception("Could not parse wpscan CLI output. "+str(err))

        else: raise Exception("Could not parse wpscan Json output and the file does not seem to be a WPScan log.\n"+str(err))

    return (( messages, warnings, alerts ))

def parse_cli(wpscan_output):
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    warning_on = False
    alert_on = False
    message=""
    # Parse the lines
    for line in wpscan_output.splitlines():
        # Remove colorization snd strip
        line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line).strip()
        # Could work with [+] etc too
        # [+] = Begin of the message
        # if message=="" and (line.startswith("[+]") or line.startswith("[i]") or line.startswith("[!]") ):
        # Toogle Warning/Alert
        if "| [!]" in line or 'insecure' in line.lower():
            warning_on = True
        elif "[!]" in line:
            alert_on = True
        # Append message line if any
        if line!="": 
            message+= line if message=="" else '\n'+line
        # End of the message just a white line. Every while line will be considered as a mesasge separator
        if line=="":
            if alert_on: alerts.append(message)
            elif warning_on: warnings.append(message)
            else: messages.append(message)
            message=""
            alert_on = False  
            warning_on = False
    # Catching last message
    if alert_on: alerts.append(message)
    elif warning_on: warnings.append(message)
    else: messages.append(message)
    return (( messages, warnings, alerts ))

def parse_results(wpscan_output, false_positives, is_json=True):
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])

    if is_json:
        (messages, warnings, alerts)=parse_json(wpscan_output)
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

def parse_a_finding(finding_type,finding):
    # Finding can be a vulnerability or other
    findingData = ""
    refData = ""
    title = "%s\n" % finding_type

    if type(finding) is dict:

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
                findingData += "\nInteresting Entries:\n"
                findingData+="\n- ".join(finding["interesting_entries"])

        # if "comfirmed_by" in finding:
        #     if len(finding["confirmed_by"]) > 0:
        #         findingData += "\nConfirmed By:\n"
        #         findingData+="\n- ".join(finding["confirmed_by"])

        # if "evidence" in finding:
        #     findingData+='Evidence: %s' % finding['evidence']

        if "references" in finding and len(finding["references"]) > 0:
            refData += "\nReferences:"
            for ref in finding["references"]:
                if ref =='cve':
                    for cve in finding["references"][ref]: refData+="\n- CVE-"+cve
                elif ref == 'wpvulndb': 
                    for wpvulndb in finding["references"][ref]: refData+="\n- WPVulnDB(%s): https://wpvulndb.com/vulnerabilities/%s" %(wpvulndb,wpvulndb)
                else:
                    refData += "\n%s: " % ref
                    refData += "\n- ".join(finding["references"][ref])

    else: raise TypeError("Must be a dict, method parse_a_finding() for data {}".format(finding)) 
    return ("%s %s" % (findingData, refData) )

def parse_findings(finding_type,findings):
    summary = []
    if type(findings) is list:
        for finding in findings:
            summary.append(parse_a_finding(finding_type,finding))
    else: raise TypeError("Must be a list, method parse_findings() for data: {}".format(findings)) 
    return(summary)

def parse_version_info(version):
    headerInfo = ""

    if "number" in version:
        headerInfo += "Running WordPress version: %s\n" % version["number"]

    if "interesting_entries" in version:
        if len(version["interesting_entries"]) > 0:
            headerInfo += "Interesting Entries: \n"
            for entries in version["interesting_entries"]:
                headerInfo += "%s\n" % entries
    return headerInfo

def parse_warning_wordpress(finding):
    summary=[]
    warn=False
    findingData=""
    if 'status' in finding and finding['status']!="latest":
        findingData+="The version of your WordPress site is out of date.\n"
        findingData+="Status %s for WP version %s" % (finding['status'], finding['number'])
        warn=True

    # if "found_by" in finding:
    #         findingData += "\nFound by: %s" % finding["found_by"]

    if "confidence" in finding:
        findingData += "\nConfidence: %s" % finding["confidence"]

    # if "interesting_entries" in finding:
    #     if len(finding["interesting_entries"]) > 0:
    #         findingData += "\nInteresting Entries:\n"
    #         findingData+="\n- ".join(finding["interesting_entries"])

    if warn: summary.append(findingData)
    return(summary)

def parse_warning_theme_or_plugin(name,finding):
    summary=[]
    warn=False
    findingData=""

    if 'slug' in finding:
        findingData+="%s\n" % finding['slug']

    if 'name' in finding:
        findingData+="%s\n" % finding['name']

    if 'outdated' in finding and finding['outdated']==True:
        findingData+="The version of your %s is out of date. The latest version is %s." % (name,finding["latest_version"])
        warn=True

    if "directory_listing" in finding and finding['directory_listing']:
        findingData+="The %s allows directory listing: %s" % (name,finding["location"])
        warn=True

    if "url" in finding:
            findingData += "\nURL: %s" % finding["url"]

    if "found_by" in finding:
        findingData += "\nFound by: %s" % finding["found_by"]

    if "confidence" in finding:
        findingData += "\nConfidence: %s" % finding["confidence"]

    if "interesting_entries" in finding:
        if len(finding["interesting_entries"]) > 0:
            findingData += "\nInteresting Entries:\n"
            findingData+="\n- ".join(finding["interesting_entries"])

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
    parser.add_argument('--input', metavar='path', help="WPScan Json or CLI output")
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    args=parse_args()
    if args.input:
        with open(args.input) as wpout:
            (infos, warnings, alerts)=parse_results( wpout.read() , [] )
    else:
        stdin=""
        lines = sys.stdin.readlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace('\n','')
        (infos, warnings, alerts)=parse_results( '\n'.join(lines) , [] )
        #print('\n'.join(lines))
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
