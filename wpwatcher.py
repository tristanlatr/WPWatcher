# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Wordpress Watcher
# Automating WPscan to scan and report vulnerable Wordpress sites
# DISCLAIMER - USE AT YOUR OWN RISK.
__version__='0.3'

import os
import re
import json
import smtplib
import traceback
import subprocess
import logging
from subprocess import CalledProcessError
import argparse
import configparser
import io
from email.mime.text import MIMEText
from datetime import datetime

configuration=None
log = logging.getLogger('wpwatcher')

# Setup logger
def init_log(verbose=False, quiet=False, logfile=None):
    format_string='%(asctime)s - %(levelname)s - %(message)s'
    format_string_cli='%(levelname)s - %(message)s'
    if verbose : verb_level=logging.DEBUG
    elif quiet : verb_level=logging.ERROR
    else : verb_level=logging.INFO
    log.setLevel(verb_level)
    std = logging.StreamHandler()
    std.setLevel(verb_level)
    std.setFormatter(logging.Formatter(format_string_cli))
    log.handlers=[]
    log.addHandler(std)
    if logfile :
        fh = logging.FileHandler(logfile)
        fh.setLevel(verb_level)
        fh.setFormatter(logging.Formatter(format_string))
        log.addHandler(fh)
    if verbose and quiet :
        log.warning("Verbose and quiet values are both set to True. By default, verbose value has priority.")
    return (log)

# Check if WPScan is installed
def is_wpscan_installed():
    try:
        result = subprocess.Popen([conf('wpscan_path'), '--version'], stdout=subprocess.PIPE).communicate()[0]
        if 'WordPress Security Scanner' in str(result): return 1
        else: return 0
    except CalledProcessError:
        return 0

# Update WPScan from github
def update_wpscan():
    log.info("Updating WPScan")
    try:
        process = subprocess.Popen([conf('wpscan_path'), '--update'], stdout=subprocess.PIPE)
        result, _  = process.communicate()
        if process.returncode :
            log.error("WPScan failed with exit code: %s \n %s" % ( str(process.returncode), str(result.decode("utf-8") ) ) )
            log.error("Error updating wpscan")
            exit(-1)
    except CalledProcessError as err:
        log.error("WPScan failed: %s" % ( str(err) ) ) 
        log.error("Error updating wpscan")
        exit(-1)

# Is the line defined as false positive
def is_false_positive(string, site_false_positives):
    # False Positive Detection
    for fp_string in conf('false_positive_strings')+site_false_positives:
        if fp_string in string:
            # print fp_string, string
            return 1
    return 0

# Parsing the results
def parse_results(results, site_false_positives, jsonformat=False):
    warnings = []
    alerts = []
    messages = []
    # --format cli
    if not jsonformat:
        warning_on = False
        alert_on = False
        message=""
        # Parse the lines
        for line in results.splitlines():
            # Remove colorization snd strip
            line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line).strip()
            # [+] = Begin of the message
            # if message=="" and (line.startswith("[+]") or line.startswith("[i]") or line.startswith("[!]") ):
            # Toogle Warning/Alert
            if "| [!]" in line or "[i]" in line:
                warning_on = True
            elif "[!]" in line:
                alert_on = True
            # Append message line if any
            if line!="": 
                message+= line if message=="" else '\n'+line
            # End of the message just a white line. Every while line will be considered as a mesasge separator
            if line=="":
                if alert_on:
                    if not is_false_positive(message, site_false_positives):
                        alerts.append(message)
                    alert_on = False 
                elif warning_on:
                    if not is_false_positive(message, site_false_positives):
                        warnings.append(message)
                    warning_on = False
                else:
                    messages.append(message)
                message="" 
        # Catching last message
        if alert_on:
            if not is_false_positive(message, site_false_positives):
                alerts.append(message)
            alert_on = False 
        elif warning_on:
            if not is_false_positive(message, site_false_positives):
                warnings.append(message)
            warning_on = False
        else:
            if not is_false_positive(message, site_false_positives):
                messages.append(message)
    else: # --format json
        # Parsing wpscan json ressources
        #           https://github.com/lukaspustina/wpscan-analyze/blob/master/src/analyze.rs
        #           https://www.thecliguy.co.uk/2019/04/26/wordcamp-london-2019-cli-tools-and-shells/
        #           https://github.com/statuscope-io/integrations/blob/master/security/check_wordpress_site.sh
        #           https://github.com/aaronweaver/AppSecPipeline/blob/master/tools/wpscan/parser.py
        #   
        try :
            data=json.loads(results)
            if data != None:
                for item in data:
                    # Parsing procedure: on specific key
                    if item == "interesting_findings":
                        if data["interesting_findings"]==None:
                            messages.append("WPScan did not find any interesting informations")
                        else:
                            # Parse informations
                            tmp_list=parse_json_findings('Interresting findings',data["interesting_findings"])
                            [ messages.append(message) for message in tmp_list if not is_false_positive(message, site_false_positives) ]
                    if item == "main_theme":
                        if data["main_theme"]==None:
                            messages.append("WPScan did not find any theme information")
                        else:
                            # Parse theme warnings
                            tmp_list=parse_json_outdated_theme_or_plugin(data['main_theme'])
                            [ warnings.append(warn) for warn in tmp_list if not is_false_positive(warn, site_false_positives) ]
                            # Parse Vulnerable themes
                            tmp_list=parse_json_findings('Vulnerable theme',data["main_theme"]["vulnerabilities"])
                            [ alerts.append(alert) for alert in tmp_list  if not is_false_positive(alert, site_false_positives) ]
                    if item == "version":
                        if data["version"]==None:
                            messages.append("WPScan did not find any WordPress version")
                        else:
                            # Parse WordPress version
                            msg=parse_json_header_info(data['version'])
                            if msg and not is_false_positive(msg, site_false_positives):
                                messages.append(msg)
                            # Parse outdated WordPress version
                            tmp_list=parse_json_outdated_wp(data['version'])
                            [ warnings.append(warn) for warn in tmp_list if not is_false_positive(warn, site_false_positives) ]
                            # Parse vulnerable WordPress version
                            tmp_list=parse_json_findings('Vulnerable wordpress',data["version"]["vulnerabilities"])
                            [ alerts.append(alert) for alert in tmp_list ]
                    if item == "plugins":
                        if data["plugins"]==None:
                            warnings.append("WPScan did not find any WordPress plugins")
                        else:
                            plugins = data[item]
                            for plugin in plugins:
                                # Parse vulnerable plugins
                                tmp_list=parse_json_findings('Vulnerable pulgin',plugins[plugin]["vulnerabilities"])
                                [ alerts.append(alert) for alert in tmp_list if not is_false_positive(alert, site_false_positives) ]
                                # Parse outdated plugins
                                tmp_list=parse_json_outdated_theme_or_plugin(plugins[plugin])
                                [ warnings.append(warn) for warn in tmp_list if not is_false_positive(warn, site_false_positives) ]
            else: 
                raise Exception("No data in wpscan Json output (data=json.loads(results)=None)")
        except Exception as err:
            raise Exception("Could not parse wpscan Json output: "+str(err))
    return ( messages, warnings, alerts )

def parse_json_header_info(version):
    headerInfo = ""
    if "number" in version:
        headerInfo += "Running WordPress version: %s\n" % version["number"]
    if "interesting_entries" in version:
        if len(version["interesting_entries"]) > 0:
            headerInfo += "Interesting Entries: \n"
            for entries in version["interesting_entries"]:
                headerInfo += "%s\n" % entries
    return headerInfo

def parse_json_outdated_wp(component):
    summary=[]
    findingData=""
    if 'status' in component and component['status']!="latest":
        findingData+="The version of your WordPress site is out of date.\n"
        findingData+="Status %s for WP version %s" % (component['status'], component['number'])
        summary.append(findingData)
    return(summary)

def parse_json_outdated_theme_or_plugin(component):
    summary=[]
    findingData=""
    if 'slug' in component:
        findingData+="%s\n" % component['slug']
    if 'outdated' in component and component['outdated']==True:
        findingData+="The version of your plugin or theme is out of date, the latest version is %s" % component["latest_version"]
        summary.append(findingData)
    return(summary)

def parse_json_findings(finding_type,findings):
    summary = []
    for finding in findings:
        findingData = ""
        refData = ""
        title = "[%s] " % finding_type
        if "title" in finding:
            title += "%s\n" % finding["title"]
        else:
            title += "%s\n" % finding["found_by"]
        findingData += "%s\n" % title
        if "fixed_in" in finding:
            findingData += "Fixed In: %s\n" % finding["fixed_in"]
        if "url" in finding:
            findingData += "URL: %s\n" % finding["url"]
        if "found_by" in finding:
            findingData += "Found by: %s\n" % finding["found_by"]
        if "confidence" in finding:
            findingData += "Confidence: %s\n" % finding["confidence"]
        if "interesting_entries" in finding:
            if len(finding["interesting_entries"]) > 0:
                findingData += "Interesting Entries: \n"
                for entries in finding["interesting_entries"]:
                    findingData += "%s\n" % entries
        if "comfirmed_by" in finding:
            if len(finding["confirmed_by"]) > 0:
                findingData += "Confirmed By: \n"
                for confirmed_by in finding["confirmed_by"]:
                    findingData += "%s\n" % confirmed_by
        if "references" in finding and len(finding["references"]) > 0:
            refData += "References:\n"
            for ref in finding["references"]:
                refData += "%s:\n" % ref
                for item in finding["references"][ref]:
                    refData += "%s\n" %  item
        ####### Individual fields ########
        summary.append("%s %s" % (findingData, refData))
    return(summary)

# Send email report
def send_report(wp_site, warnings=None, alerts=None, infos=None, errors=None, emails=None, status=None):
    if emails: to_email=','.join( emails )
    else: to_email = ','.join( wp_site['email_to'] + conf('email_to') )
    if to_email != "":
        log.info("Sending WPWatcher email report of %s to %s" % (wp_site['url'], to_email))
        try:
            if (warnings or alerts) :message = "Issues have been detected by WPScan.\nSite: %s" % (wp_site['url'])
            else: message = "WPScan report\nSite: %s" % (wp_site['url'])
            if errors:
                message += "\n\n\tErrors\n\n"
                message += "\n\n".join(errors)
            if alerts:
                message += "\n\n\tAlerts\n\n"
                message += "\n\n".join(alerts)
            if warnings:
                message += "\n\n\tWarnings\n\n"
                message += "\n\n".join(warnings)
            if infos:
                message += "\n\n\tInformations\n\n"
                message += "\n\n".join(infos)
            mime_msg = MIMEText(message)
            mime_msg['Subject'] = 'WPWatcher%s report on %s - %s' % (' '+status if status else '',wp_site['url'], get_timestamp())
            mime_msg['From'] = conf('from_email')
            mime_msg['To'] = to_email
            # SMTP Connection
            s = smtplib.SMTP(conf('smtp_server'))
            s.ehlo()
            # SSL
            if conf('smtp_ssl'):
                s.starttls()
            # SMTP Auth
            if conf('smtp_auth'):
                s.login(conf('smtp_user'), conf('smtp_pass'))
            # Send Email
            s.sendmail(conf('from_email'), to_email, mime_msg.as_string())
            s.quit()
            return(0)
        except Exception as err:
            log.error(str(err))
            log.error("Unable to send mail report of " + wp_site['url'] + "to " + to_email)
            return(False)
    else:
        log.warning("Not sending email report since no email are configured")

def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def find_config_file():
        '''
        Returns the location of a existing `wpwatcher.conf` file.  
        Will return ./wpwatcher.conf or ~/wpwatcher.conf
        '''
        if os.path.isfile('./wpwatcher.conf'): conf_path='./wpwatcher.conf'
        elif 'APPDATA' in os.environ: conf_path=(os.path.join(os.environ['APPDATA'],'wpwatcher.conf'))
        elif 'XDG_CONFIG_HOME' in os.environ: conf_path=(os.path.join(os.environ['XDG_CONFIG_HOME'],'wpwatcher.conf'))
        elif 'HOME' in os.environ: conf_path=(os.path.join(os.environ['HOME'],'wpwatcher.conf'))
        if not os.path.isfile(conf_path) : return False
        return(conf_path)

def read_config(configpath):
    global configuration
    # Load the configuration file
    try:
        configuration = configparser.ConfigParser()
        #Default config
        configuration.read_dict({
                'wpwatcher':{
                        'wp_sites' :"""[{"url":""}]""",
                        'false_positive_strings' : """["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]""",                        
                        'wpscan_path':'wpscan',
                        'log_file':"",
                        'wpscan_args': """["--no-banner","--format","cli","--random-user-agent","--disable-tls-checks"]""",
                        'send_email_report':'No',
                        'always_send_reports':'No',
                        'email_to':"""[""]""",
                        'email_errors_to':"""[""]""",
                        'send_warnings':'Yes',
                        'send_infos':'No',
                        'smtp_server':"",
                        'smtp_auth':'No',
                        'smtp_user':"",
                        'smtp_pass':"",
                        'smtp_ssl':'No',
                        'from_email':"",
                        'quiet':'No',
                        'verbose':'No'
                }
        })
        if len(configuration.read(configpath))==0:
            return False
    except Exception as err: 
        log.error(err)
        return False
    return True

def conf(key):
    if configuration:
        # Boolean conf values
        if key in ['send_email_report', 'smtp_auth', 'smtp_ssl', 'verbose', 'quiet', 'always_send_reports', 'send_infos', 'send_warnings']:
            return configuration.getboolean('wpwatcher', key)
        # JSON lists conf values
        elif key in ['wp_sites', 'email_to', 'wpscan_args', 'false_positive_strings', 'email_errors_to']:
            string_val=configuration.get('wpwatcher', key)
            try:
                loaded=json.loads(string_val)
            except Exception as err:
                log.error(err)
                log.error("Could not read JSON value of key: %s for string: %s. Error: %s" % (key, configuration.get('wpwatcher',key), str(err)))
                exit(-1)
            return loaded if loaded else []
        # Default conf values
        else:
            return configuration.get('wpwatcher', key)
    else:
        log.error("No configuration")
        exit(-1)

def parse_args():

    parser = argparse.ArgumentParser(description='Wordpress Watcher. Automating WPscan to scan and report vulnerable Wordpress sites')
    parser.add_argument('--conf', metavar='Config file', help="Path to the config file. Will use ./wpwatcher.conf or ~/wpwatcher.conf if left none")
    args = parser.parse_args()
    return args

# Run WPScan on defined domains
def run_scan():
    log.info("Starting scans on configured sites")
    exit_code=0
    for wp_site in conf('wp_sites'):
        # Init scan variables
        errors=[]
        (messages, warnings, alerts)=([],[],[])
        # Read the wp_site dict and assing default values if needed ----------
        if 'url' not in wp_site or wp_site['url']=="":
            log.error("Site must have valid a 'url' key: %s" % (str(wp_site)))
            exit_code=-1
            continue
        if 'email_to' not in wp_site or wp_site['email_to'] is None: wp_site['email_to']=[]
        if 'false_positive_strings' not in wp_site or wp_site['false_positive_strings'] is None: wp_site['false_positive_strings']=[]
        if 'wpscan_args' not in wp_site or wp_site['wpscan_args'] is None: wp_site['wpscan_args']=[]
        wordpress_arguments=conf('wpscan_args')+wp_site['wpscan_args']
        
        # Scan ----------------------------------------------------------------
        try:
            cmd=[conf('wpscan_path')] + wordpress_arguments + ['--url', wp_site['url']]
            log.info("Scanning '%s' with command: %s" % (wp_site['url'], ' '.join(cmd)))
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE )
            result, _  = process.communicate()
            if process.returncode :
                # Handle scan error
                result=result.decode("utf-8")
                err_string="WPScan failed with exit code for site %s: %s. Output: \n%s" % (wp_site['url'], str(process.returncode), result)
                log.error(" ".join(line.strip() for line in err_string.splitlines()))
                errors.append(err_string)
                exit_code=-1
                # Skip this failling wpscan if nomail
                if conf('always_send_reports') == False or conf('send_email_report') == False: 
                    continue
            else:
                # Scan success
                result=result.decode("utf-8")
                log.debug("WPScan raw output:\n"+result)
                pass
        except CalledProcessError as err:
            # Handle scan error
            result=str(err)
            err_string="WPScan failed with exit code for site %s: %s. Output: \n%s" % (wp_site['url'], str(process.returncode), result)
            log.error(" ".join(line.strip() for line in err_string.splitlines()))
            errors.append(err_string)
            exit_code=-1
            # Skip this failling wpscan if nomail
            if conf('always_send_reports') == False or conf('send_email_report') == False: 
                    continue
        
        # Parse the results if no errors with wpscan ---------------------------
        if len(errors)==0:
            try:
                # Test if Json selectted in wpscan args, get last '--format' element occurrence and check if the next parameter is 'json'
                if '--format' in wordpress_arguments: 
                    format_index=len(wordpress_arguments) - 1 - wordpress_arguments[::-1].index('--format')
                    is_json=wordpress_arguments[format_index+1]=='json'
                else: is_json=False
                log.debug("Parsing WPScan %s output" % 'json' if is_json else 'cli')
                (messages, warnings, alerts) = parse_results(result , wp_site['false_positive_strings'] , jsonformat=is_json )
            except Exception as err:
                err_string="Could not parse the results from wpscan command for site {}. Error: {}".format(wp_site['url'],str(err))
                log.error(err_string)
                errors.append(err_string)
                exit_code=-1
                # Skip this failling wpscan if nomail
                if conf('always_send_reports') == False or conf('send_email_report') == False: 
                    continue
                else: errors.append("WPScan output: \n"+result)
            # Report Options ------------------------------------------------------
            # Logfile
            for message in messages:
                log.info("** WPScan INFO %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(message).splitlines())))
            for warning in warnings:
                log.warning("** WPScan WARNING %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(warning).splitlines()) ))
            for alert in alerts:
                log.critical("** WPScan ALERT %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(alert).splitlines())))
        # Email errors -------------------------------------------------------
        if len(errors)>0 :
            if conf('send_email_report') and len(conf('email_errors_to'))>0:
                if not send_report(wp_site, warnings, alerts, infos=messages, errors=errors, emails=conf('email_errors_to'), status="ERROR"):
                    # Send report failed
                    exit_code=-1
            elif conf('send_email_report'): 
                if not send_report(wp_site, warnings, alerts, infos=messages, errors=errors, status="ERROR"):
                    # Send report failed
                    exit_code=-1
            else: log.info("No WPWatcher ERROR email report have been sent for site %s."%wp_site)
        # Email -------------------------------------------------------------------
        elif conf('send_email_report'):
            status=None
            if len(warnings)>0 and len(alerts) == 0:
                status='WARNING'
            elif len(alerts)>0:
                status='ALERT'
            if conf('send_infos') or ( status=="WARNING" and conf('send_warnings') ) or status=='ALERT':
                if not send_report(wp_site, alerts=alerts,
                    warnings=warnings if conf('send_warnings') else None,
                    infos=messages if conf('send_infos') else None,
                    status=status):
                    # Send report failed
                    exit_code=-1
            else: log.info("No WPWatcher %s email report have been sent for site %s. If you want to receive emails all the time, set send_infos=Yes in the config."%(status,wp_site))
    if exit_code == 0:
        log.info("Scans finished successfully.") 
    else:
        log.info("Scans finished with errors.") 
    return(exit_code)

if __name__ == '__main__':
    init_log()
    args=parse_args()
    # Read config
    configpath=None
    if args.conf: 
        configpath=args.conf
    else:
        if not find_config_file():
            log.error("Could not find config file")
            exit(-1)
        else:
            configpath=find_config_file()
    if not read_config(configpath):
        log.error("Could not read config " + str(configpath))
        exit(-1)
    # Init logger with config
    init_log(verbose=conf('verbose'),
        quiet=conf('quiet'),
        logfile=conf('log_file'))
    log.info("Read config file %s" % (configpath))

    # Check if WPScan exists
    if not is_wpscan_installed():
        log.error("WPScan not installed.\nPlease install wpscan on your system.\nSee https://wpscan.org for installation steps.")
        exit(-1)
    else:
        update_wpscan()
    if conf('wp_sites') and type(conf('wp_sites')) is list and len(conf('wp_sites'))>0:
        # Run Scan
        exit(run_scan())
    else:
        log.error("No site to monitor. Please configure monitored sites in the config file")