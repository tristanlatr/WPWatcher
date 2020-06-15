""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import io
import re
import smtplib
import socket
import traceback
import threading
import time
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from wpwatcher import log, VERSION
from wpwatcher.utils import get_valid_filename

# Date format used everywhere
DATE_FORMAT='%Y-%m-%dT%H-%M-%S'

# Sendmail call will be done one at a time not over load server and create connection errors
mail_lock = threading.Lock()

class WPWatcherNotification():
    
    def __init__(self, conf):
        # store specific mailserver values
        self.from_email=conf['from_email']
        self.smtp_server=conf['smtp_server']
        self.smtp_ssl=conf['smtp_ssl']
        self.smtp_auth=conf['smtp_auth']
        self.smtp_user=conf['smtp_user']
        self.smtp_pass=conf['smtp_pass']

        #store specific notification values
        self.send_email_report=conf['send_email_report']
        self.email_to=conf['email_to']
        self.email_errors_to=conf['email_errors_to']
        self.send_warnings=conf['send_warnings']
        self.send_infos=conf['send_infos']
        self.send_errors=conf['send_errors']
        self.attach_wpscan_output=conf['attach_wpscan_output']
        self.resend_emails_after=conf['resend_emails_after']

        # and copy config as is
        # self.conf=conf
        # mail server, will be created when sending mails
        self.server=None

    def notify(self, wp_site, wp_report, last_wp_report):
        # Will print parsed readable Alerts, Warnings, etc as they will appear in email reports
        log.debug("\n%s\n"%(WPWatcherNotification.build_message(wp_report, 
                warnings=self.send_warnings or self.send_infos, # switches to include or not warnings and infos
                infos=self.send_infos)))
        if self.should_notify(wp_report, last_wp_report):
            self._notify(wp_site, wp_report, last_wp_report)
        else: return False

    def send_mail(self, message, to):
        # Connecting and sending
        self.server = smtplib.SMTP(self.smtp_server)
        self.server.ehlo_or_helo_if_needed()
        # SSL
        if self.smtp_ssl: self.server.starttls()
        # SMTP Auth
        if self.smtp_auth: self.server.login(self.smtp_user, self.smtp_pass)
        # Send Email
        self.server.sendmail(self.from_email, to, message.as_string())
        self.server.quit()

    # Send email report with status and timestamp
    def send_report(self, wp_report, email_to) : #, send_infos=False, send_warnings=True, send_errors=False, attach_wpscan_output=False):

        # Building message
        message = MIMEMultipart("html")
        message['Subject'] = 'WPWatcher %s report - %s - %s' % (  wp_report['status'], wp_report['site'], wp_report['datetime'])
        message['From'] = self.from_email
        message['To'] = email_to

        # Email body
        body=self.build_message(wp_report, 
            warnings=self.send_warnings or self.send_infos, # switches to include or not warnings and infos
            infos=self.send_infos )

        message.attach(MIMEText(body))
        
        # Attachment log if attach_wpscan_output
        if self.attach_wpscan_output:
            # Remove color
            wp_report['wpscan_output'] = re.sub(r'(\x1b|\[[0-9][0-9]?m)','', str(wp_report['wpscan_output']))
            # Read the WPSCan output
            attachment=io.BytesIO(wp_report['wpscan_output'].encode())
            part = MIMEApplication(
                attachment.read(),
                Name='WPScan_output'
            )
            # Sanitize WPScan report filename 
            wpscan_report_filename=get_valid_filename('WPScan_output_%s_%s' % (wp_report['site'], wp_report['datetime']))
            # Add header as key/value pair to attachment part
            part.add_header(
                "Content-Disposition",
                "attachment; filename=%s.txt"%(wpscan_report_filename),
            )
            # Attach the report
            message.attach(part)
            log.info("%s attached"%(wpscan_report_filename))
        else: log.info("No file attached, set attach_wpscan_output=Yes or use --attach to attach WPScan output to emails")
        # # Connecting and sending
        self.send_mail(message, email_to)

        # Store report time
        wp_report['last_email']=datetime.now().strftime(DATE_FORMAT)
        # Discard fixed items because infos have been sent
        wp_report['fixed']=[]
        log.info("Email sent: %s to %s" % (message['Subject'], email_to))

    def should_notify(self, wp_report, last_wp_report):
        should=True
        if not wp_report: return False
        
        # Return if email seding is disable
        if not self.send_email_report:
            # No report notice
            log.info("Not sending WPWatcher %s email report for site %s. To receive emails, setup mail server settings in the config and enable send_email_report or use --send."%(wp_report['status'], wp_report['site']))
            should=False
        
        # Return if error email and disabled
        elif wp_report['status']=="ERROR" and not self.send_errors:
            log.info("Not sending WPWatcher ERROR email report for site %s because send_errors=No. If you want to receive error emails, set send_errors=Yes in the config or use --errors."%(wp_report['site']))
            should=False
        
        # Regular mail filter with --warnings or --infos
        elif wp_report['status']=="WARNING" and not self.send_warnings and not self.send_infos :
            log.info("Not sending WPWatcher WARNING email report for site %s because send_warnings=No. If you want to receive warning emails, set send_warnings=Yes in the config or use --infos."%(wp_report['site']))
            should=False

        elif wp_report['status']=="INFO" and not self.send_infos:
            # No report notice
            log.info("Not sending WPWatcher INFO email report for site %s because send_infos=No. If you want to receive infos emails, set send_infos=Yes in the config or use --infos."%(wp_report['site']))
            should=False

        if wp_report['last_email'] and datetime.strptime(wp_report['datetime'],DATE_FORMAT) - datetime.strptime(wp_report['last_email'],DATE_FORMAT) < self.resend_emails_after and ( not last_wp_report or last_wp_report['status']!=wp_report['status'] ) :
            # No report notice
            log.info("Not sending WPWatcher %s email report for site %s because already sent in the last %s."%(wp_report['status'], wp_report['site'], self.resend_emails_after))
            should=False

        
        return should

    def _notify(self, wp_site, wp_report, last_wp_report):

        # Send the report to
        if len(self.email_errors_to)>0 and wp_report['status']=='ERROR':
            to = ','.join( self.email_errors_to )
        else: 
            to = ','.join( wp_site['email_to'] + self.email_to )

        if not to :
            log.info("Not sending WPWatcher %s email report because no email is configured for site %s"%(wp_report['status'], wp_report['site']))
            return

        while mail_lock.locked(): 
            time.sleep(0.01)

        try:
            with mail_lock:
                self.send_report(wp_report, to)
                return True
                
        # Handle send mail error
        except (smtplib.SMTPException, ConnectionRefusedError):
            log.error("Unable to send mail report for site " + wp_site['url'] + "\n" + traceback.format_exc())
            wp_report['errors'].append("Unable to send mail report for site " + wp_site['url'] + "\n" + traceback.format_exc())
            raise RuntimeError("Unable to send mail report")
            # Fail fast
            #  if not self.check_fail_fast(): return False 

    @staticmethod
    def build_message(wp_report, warnings=True, infos=False):
        
        message="WordPress security scan report for site: %s\n" % (wp_report['site'])
        message+="Scan datetime: %s\n" % (wp_report['datetime'])
        
        if wp_report['errors'] : message += "\nAn error occurred."
        elif wp_report['alerts'] : message += "\nVulnerabilities have been detected by WPScan."
        elif wp_report['warnings']: message += "\nIssues have been detected by WPScan."
        if wp_report['fixed']: message += "\nSome issues have been fixed since last scan."

        message += WPWatcherNotification.format_issues('Errors',wp_report['errors'])
        message += WPWatcherNotification.format_issues('Alerts',wp_report['alerts'])
        message += WPWatcherNotification.format_issues('Fixed',wp_report['fixed'])
        if warnings: message += WPWatcherNotification.format_issues('Warnings',wp_report['warnings'])
        if infos: message += WPWatcherNotification.format_issues('Informations',wp_report['infos'])
                
        message += "\n\n--"
        message += "\nWPWatcher -  Automating WPscan to scan and report vulnerable Wordpress sites"
        message += "\nServer: %s - Version: %s\n"%(socket.gethostname(),VERSION)
        return message

    
    @staticmethod
    def format_issues(title, issues):
        message=""
        if issues:
            message += "\n\n\t%s\n\t%s\n\n"%(title, '-'*len(title))+"\n\n".join(issues)
        return message