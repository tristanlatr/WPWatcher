""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import io
import re
import smtplib
import socket
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from wpwatcher import log, VERSION
from wpwatcher.utils import get_valid_filename

class WPWatcherNotification():
    
    def __init__(self, smtp_server, from_email, smtp_ssl=False, smtp_auth=False, smtp_user=None, smtp_pass=None):
        self.from_email=from_email
        self.smtp_server=smtp_server
        self.smtp_ssl=smtp_ssl
        self.smtp_auth=smtp_auth
        self.smtp_user=smtp_user
        self.smtp_pass=smtp_pass

    @staticmethod
    def build_message(wp_report, warnings=True, infos=False):
        
        message="WordPress security scan report for site: %s\n" % (wp_report['site'])
        message+="Scan datetime: %s\n" % (wp_report['datetime'])
        
        if wp_report['errors'] : message += "\nAn error occurred."
        elif wp_report['alerts'] : message += "\nVulnerabilities have been detected by WPScan."
        elif wp_report['warnings']: message += "\nIssues have been detected by WPScan."
        if wp_report['fixed']: message += "\nSome issues have been fixed since last scan."
        
        if wp_report['errors']:
            message += "\n\n\tErrors\n\t------\n\n"
            message += "\n\n".join(wp_report['errors'])
        if wp_report['alerts']:
            message += "\n\n\tAlerts\n\t------\n\n"
            message += "\n\n".join(wp_report['alerts'])
        if wp_report['fixed']:
            message += "\n\n\tFixed\n\t-----\n\n"
            message += "\n\n".join(wp_report['fixed'])
        if wp_report['warnings'] and warnings :
            message += "\n\n\tWarnings\n\t--------\n\n"
            message += "\n\n".join(wp_report['warnings'])
        if wp_report['infos'] and infos :
            message += "\n\n\tInformations\n\t------------\n\n"
            message += "\n\n".join(wp_report['infos'])
        
        message += "\n\n--"
        message += "\nWPWatcher -  Automating WPscan to scan and report vulnerable Wordpress sites"
        message += "\nServer: %s - Version: %s\n"%(socket.gethostname(),VERSION)
        return message

    # Send email report with status and timestamp
    def send_report(self, wp_report, email_to, send_infos=False, send_warnings=True, send_errors=False, attach_wpscan_output=False):
        # To
        # if len(self.conf['email_errors_to'])>0 and wp_report['status']=='ERROR':
        #     to_email = ','.join( self.conf['email_errors_to'] )
        # else: 
        #     to_email = ','.join( wp_site['email_to'] + self.conf['email_to'] )
        # Build the email report string
        

        if email_to != "":
            
            # Building message
            message = MIMEMultipart("html")
            message['Subject'] = 'WPWatcher %s report - %s - %s' % (  wp_report['status'], wp_report['site'], wp_report['datetime'])
            message['From'] = self.from_email
            message['To'] = email_to

            # Email body
            body=self.build_message(wp_report, 
                warnings=send_warnings or send_infos, # switches to include or not warnings and infos
                infos=send_infos )

            message.attach(MIMEText(body))
            
            # Attachment log if attach_wpscan_output
            if attach_wpscan_output:
                # Remove color
                wp_report['wpscan_output'] = re.sub(r'(\x1b|\[[0-9][0-9]?m)','', str(wp_report['wpscan_output']))
                # Read the WPSCan output
                attachment=io.BytesIO(wp_report['wpscan_output'].encode())
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                # Encode file in ASCII characters to send by email    
                encoders.encode_base64(part)
                # Sanitize WPScan report filename 
                wpscan_report_filename=get_valid_filename('WPScan_output_%s_%s' % (wp_report['site'], wp_report['datetime']))
                # Add header as key/value pair to attachment part
                part.add_header(
                    "Content-Disposition",
                    "attachment; filename=%s.txt"%(wpscan_report_filename),
                )
                # Attach the report
                message.attach(part)

            # Connecting and sending
            # SMTP Connection
            s = smtplib.SMTP(self.smtp_server)
            s.ehlo()
            # SSL
            if self.smtp_ssl:
                s.starttls()
            # SMTP Auth
            if self.smtp_auth:
                s.login(self.smtp_user, self.smtp_pass)
            # Send Email
            s.sendmail(self.from_email, email_to, message.as_string())
            s.quit()
            # Store report time
            wp_report['last_email']=datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
            # Discard fixed items because infos have been sent
            wp_report['fixed']=[]
            log.info("Email sent: %s to %s" % (message['Subject'], email_to))
        else:
            log.info("Not sending WPWatcher %s email report because no email is configured for site %s"%(wp_report['status'], wp_report['site']))

