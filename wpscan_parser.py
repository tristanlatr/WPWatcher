#! /usr/bin/env python3
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
import json
import re
import sys
import argparse
# WPScan output parser
# DISCLAIMER - USE AT YOUR OWN RISK.
# 
# Some infos are intentionally ignored when parsing Json to have shorter output.
# You can use --format cli to show all informations with Infos, Warnings and Alerts
# 
# Exemple stdin usage:
#   $ wpscan --url https://exemple.com --format json | python3 ./wpscan_parser.py
#
# With param --input :
#   $ python3 ./wpscan_parser.py --input wpscan.log
#
# Or you can import this package into your application and call `parse_results` method.
#   from wpscan_parser import parse_results
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

def parse_json(data):
     # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])

    # try :
    if True:
        # data=json.loads(wpscan_output)
        # Do a sanity check to confirm the data is ok
        if data and 'target_url' in data and data['target_url']:

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
                if data["interesting_findings"]==None or len(data["interesting_findings"])==0:
                    messages.append("WPScan did not find any interesting informations")
                else:
                    # Parse informations
                    messages.extend(parse_findings('Interesting finding', data["interesting_findings"]) )
            
            if "main_theme" in data:
                if data["main_theme"]==None or len(data["main_theme"])==0:
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
                if data["version"]==None or len(data["version"])==0:
                    messages.append("WPScan did not find any WordPress version")
                else:
                    # Parse WordPress version
                    messages.append(parse_version_info(data['version']))
                    # Parse outdated WordPress version
                    warnings.extend(parse_warning_wordpress(data['version']) )
                    # Parse vulnerable WordPress version
                    alerts.extend(parse_findings('Vulnerable wordpress',data["version"]["vulnerabilities"]) )
            
            if "themes" in data:
                if data["themes"]==None or len(data["themes"])==0:
                    messages.append("WPScan did not find any theme information")
                else:
                    for theme in data["themes"]:
                        # Parse secondary theme warnings
                        warnings.extend(parse_warning_theme_or_plugin('theme',theme) )
                        # Parse secondary Vulnerable themes
                        alerts.extend(parse_findings('Vulnerable theme', data["themes"][theme]["vulnerabilities"]) )
            
            if "plugins" in data:
                if data["plugins"]==None or len(data["plugins"])==0:
                    messages.append("WPScan did not find any WordPress plugins")
                else:
                    plugins = data["plugins"]
                    for plugin in plugins:
                        # Parse vulnerable plugins
                        alerts.extend(parse_findings('Vulnerable pulgin',plugins[plugin]["vulnerabilities"]) )
                        # Parse outdated plugins
                        warnings.extend(parse_warning_theme_or_plugin('plugin',plugins[plugin]) )

            if "users" in data:
                if data["users"]==None or len(data["users"])==0:
                    messages.append("WPScan did not find any WordPress users")
                else:
                    users = data["users"]
                    for name in users:
                        # Parse users users
                        messages.append( 'WordPress user found: %s'%name )
            
            if "config_backups" in data:
                if data["config_backups"]==None or len(data["config_backups"])==0:
                    messages.append("WPScan did not find any WordPress config backups")
                else:
                    for url in data['config_backups']:
                        alerts.append("WordPress Configuration Backup Found\nURL: %s"%str(url) )

            if "db_exports" in data :
                if data['db_exports']==None or len(data['db_exports'])==0:
                    messages.append("WPScan did not find any WordPress db exports")
                else:
                    alerts.extend(parse_findings("WordPress Database Export Found", data['db_exports'] ))

            if "timthumbs" in data :
                if data['timthumbs']==None or len(data['timthumbs'])==0:
                    messages.append("WPScan did not find any timthumbs")
                else:
                    for tt in data['timthumbs']:
                        if "vulnerabilities" in tt and tt["vulnerabilities"]!=None:
                            alerts.extend(parse_findings("Timthumbs Vulnerability",data['timthumbs'][tt]["vulnerabilities"]) )
                        messages.extend(parse_findings("Timthumb" , data['timthumbs'][tt]) )

            if "password_attack" in data :
                if data['password_attack']==None or len(data['password_attack'])==0:
                    messages.append("WPScan did not find any valid passwords")
                else:
                    for passwd in data['password_attack']:
                        alerts.append("WordPres Weak User Password Found:\n%s"%str(passwd) )

            if "medias" in data :
                if data['medias']==None or len(data['medias'])==0:
                    messages.append("WPScan did not find any medias")
                else:
                    warnings.extend(parse_findings("WordPress Media found", data['medias'] ))

            if "vuln_api" in data :
                if "error" in data['vuln_api']:
                    warnings.append(data['vuln_api']["error"])

            if "not_fully_configured" in data and data['not_fully_configured']!=None :
                alerts.append(data['not_fully_configured'])

        else: 
            raise Exception("No data in wpscan Json output (None) or no 'target_url' field present in the provided Json data. The scan might have failed, data: \n"+str(data))
    
    # except Exception as err:
    #     # Default parsing is json, if fails will try cli
    #     try: (messages, warnings, alerts)=parse_cli(wpscan_output)
    #     except Exception as err2: 
    #         raise Exception("Could not parse wpscan Json output. Error:\n"+str(err)+"\nCould not parse neither CLI output: "+str(err2))

    return (( messages, warnings, alerts ))

def parse_a_finding(finding_type,finding):
    # Finding can be a vulnerability or other
    findingData = ""
    refData = ""
    title = "%s:" % finding_type

    if type(finding) is dict:
        if "type" in finding:
            title += " [%s]" % finding["type"]

        if "title" in finding:
            title += " %s" % finding["title"]

        if "to_s" in finding:
            title += " %s" % finding["to_s"]

        findingData += "%s" % title

        if "fixed_in" in finding:
            findingData += "\nFixed In: %s" % finding["fixed_in"]

        if "url" in finding:
            findingData += "\nURL: %s" % finding["url"]

        # if "found_by" in finding:
        #     findingData += "\nFound by: %s" % finding["found_by"]

        # if "confidence" in finding:
        #     findingData += "\nConfidence: %s" % finding["confidence"]

        if "interesting_entries" in finding:
            if len(finding["interesting_entries"]) > 0:
                findingData += "\nInteresting Entries: %s" % (", ".join(finding["interesting_entries"]))

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
                    refData += "\n  %s: %s" % (ref, ", ".join(finding["references"][ref]) )

    else: raise TypeError("Must be a dict, method parse_a_finding() for data {}".format(finding)) 
    return ("%s %s" % (findingData, refData) )

# Wrapper to parse findings can take list or dict type
def parse_findings(finding_type,findings):
    summary = []
    if type(findings) is list:
        for finding in findings:
            summary.append(parse_a_finding(finding_type,finding))
    elif type(findings) is dict:
        for finding in findings:
            summary.append(parse_a_finding(finding_type,findings[finding]))
    else:
        raise TypeError("Must be a list or dict, method parse_findings() for data: {}".format(findings)) 
    return(summary)

def parse_version_info(version):
    headerInfo = ""

    if "number" in version:
        headerInfo += "Running WordPress version: %s\n" % version["number"]

    if "interesting_entries" in version:
            if len(version["interesting_entries"]) > 0:
                headerInfo += "\nInteresting Entries: %s" % (", ".join(version["interesting_entries"]))

    return headerInfo

def parse_warning_wordpress(finding):
    summary=[]
    warn=False
    findingData=""
    if 'status' in finding and finding['status']!="latest":
        findingData+="The version of your WordPress site is out of date.\n"
        findingData+="Status %s for version %s" % (finding['status'], finding['number'])
        warn=True

    # if "found_by" in finding:
    #         findingData += "\nFound by: %s" % finding["found_by"]

    # if "confidence" in finding:
    #     findingData += "\nConfidence: %s" % finding["confidence"]

    # if "interesting_entries" in finding:
    #         if len(finding["interesting_entries"]) > 0:
    #             findingData += "\nInteresting Entries: %s" % (", ".join(finding["interesting_entries"]))

    if warn: summary.append(findingData)
    return(summary)

def parse_warning_theme_or_plugin(finding_type,finding):
    summary=[]
    warn=False
    findingData=""

    if 'slug' in finding:
        findingData+="%s" % finding['slug']
    
    if "location" in finding:
            findingData += "\nLocation: %s" % finding["location"]

    if 'outdated' in finding and finding['outdated']==True:
        findingData+="\nThe version of your %s is out of date. The latest version is %s." % (finding_type,finding["latest_version"])
        warn=True

    if "directory_listing" in finding and finding['directory_listing']:
        findingData+="\nThe %s allows directory listing: %s" % (finding_type,finding["location"])
        warn=True

    if "error_log_url" in finding and finding['error_log_url']:
        findingData+="\nThe %s error log accessible: %s" % (finding_type,finding["error_log_url"])
        warn=True

    # if "found_by" in finding:
    #     findingData += "\nFound by: %s" % finding["found_by"]

    # if "confidence" in finding:
    #     findingData += "\nConfidence: %s" % finding["confidence"]

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
    parser.add_argument('--input', metavar='path', help="WPScan Json or CLI output")
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
