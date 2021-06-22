"""
Email notifications.
"""
from typing import Dict, Any, List, Optional
import io
import re
import smtplib
import threading
import time
from string import Template
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from wpscan_out_parse.formatter import format_results, format_issues
from wpwatcher import log
from wpwatcher.__version__ import __version__
from wpwatcher.utils import get_valid_filename

# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"

class EmailSender:
    """
    Handles the email nofification logic. 
    """

    def __init__(self, conf: Dict[str, Any]):
        # store specific mailserver values
        self.from_email: str = conf["from_email"]
        self.smtp_server: str = conf["smtp_server"]
        self.smtp_ssl: bool = conf["smtp_ssl"]
        self.smtp_auth: bool = conf["smtp_auth"]
        self.smtp_user: str = conf["smtp_user"]
        self.smtp_pass: str = conf["smtp_pass"]

        # store specific notification values
        self.send_email_report: bool = conf["send_email_report"]
        self.email_to: List[str] = conf["email_to"]
        self.email_errors_to: List[str] = conf["email_errors_to"]
        self.send_warnings: bool = conf["send_warnings"]
        self.send_infos: bool = conf["send_infos"]
        self.send_errors: bool = conf["send_errors"]
        self.attach_wpscan_output: bool = conf["attach_wpscan_output"]
        self.resend_emails_after: timedelta = conf["resend_emails_after"]

        # mail server, will be created when sending mails
        self.server: Optional[smtplib.SMTP] = None

        self.use_monospace_font: bool = conf["use_monospace_font"]

        # Sendmail call will be done one at a time not over load server and create connection errors
        self._mail_lock = threading.Lock()

    def notify(
        self,
        wp_site: Dict[str, Any],
        wp_report: Dict[str, Any],
        last_wp_report: Optional[Dict[str, Any]],
        wpscan_command: str,
    ) -> bool:
        """Email recipients if match `should_notify` conditions"""
        if self.should_notify(wp_report, last_wp_report):
            self.send_report(wp_site, wp_report, wpscan_command)
            return True
        else:
            return False

    def _send_mail(self, message: MIMEMultipart, email_to: List[str]) -> None:
        """Raw sendmail"""
        # Connecting and sending
        self.server = smtplib.SMTP(self.smtp_server)
        self.server.ehlo_or_helo_if_needed()
        # SSL
        if self.smtp_ssl:
            self.server.starttls()
        # SMTP Auth
        if self.smtp_auth:
            self.server.login(self.smtp_user, self.smtp_pass)
        # Send Email
        self.server.sendmail(self.from_email, email_to, message.as_string())
        self.server.quit()

    # Send email report with status and timestamp
    def _send_report(
        self, wp_report: Dict[str, Any], email_to: List[str], wpscan_command: str
    ) -> None:
        """Build MIME message based on report and call send_mail"""

        # Building message
        message = MIMEMultipart("html")
        message[
            "Subject"
        ] = f"WPWatcher {wp_report['status']} report - {wp_report['site']} - {wp_report['datetime']}"
        message["From"] = self.from_email
        message["To"] = ",".join(email_to)

        # Email body
        body = self.build_message(wp_report, wpscan_command)
        if self.use_monospace_font:
            body = (
                f'<font face="Courier New, Courier, monospace" size="-1">{body}</font>'
            )

        message.attach(MIMEText(body, "html"))

        # Attachment log if attach_wpscan_output
        if self.attach_wpscan_output:
            # Remove color
            wp_report["wpscan_output"] = re.sub(
                r"(\x1b|\[[0-9][0-9]?m)", "", str(wp_report["wpscan_output"])
            )
            # Read the WPSCan output
            attachment = io.BytesIO(wp_report["wpscan_output"].encode())
            part = MIMEApplication(attachment.read(), Name="WPScan_output")
            # Sanitize WPScan report filename
            wpscan_report_filename = get_valid_filename(
                f"WPScan_output_{wp_report['site']}_{wp_report['datetime']}"
            )
            # Add header as key/value pair to attachment part
            part.add_header(
                "Content-Disposition",
                f"attachment; filename={wpscan_report_filename}.txt",
            )
            # Attach the report
            message.attach(part)
        
        # Connecting and sending
        self._send_mail(message, email_to)
        log.info(f"Email sent: {message['Subject']} to {email_to}")

    def should_notify(
        self, wp_report: Dict[str, Any], last_wp_report: Optional[Dict[str, Any]]
    ) -> bool:
        """Determine if the notification should be sent"""
        should = True
        if not wp_report:
            return False

        # Return if email seding is disable
        if not self.send_email_report:
            # No report notice
            log.info(
                f"Not sending WPWatcher {wp_report['status']} email report for site {wp_report['site']}. To receive emails, setup mail server settings in the config and enable send_email_report or use --send."
            )
            should = False

        # Return if error email and disabled
        elif wp_report["status"] == "ERROR" and not self.send_errors:
            log.info(
                f"Not sending WPWatcher ERROR email report for site {wp_report['site']} because send_errors=No. If you want to receive error emails, set send_errors=Yes in the config or use --errors."
            )
            should = False

        # Regular mail filter with --warnings or --infos
        elif (
            wp_report["status"] == "WARNING"
            and not self.send_warnings
            and not self.send_infos
        ):
            log.info(
                f"Not sending WPWatcher WARNING email report for site {wp_report['site']} because send_warnings=No. If you want to receive warning emails, set send_warnings=Yes in the config or use --infos."
            )
            should = False

        elif wp_report["status"] == "INFO" and not self.send_infos:
            # No report notice
            log.info(
                f"Not sending WPWatcher INFO email report for site {wp_report['site']} because send_infos=No. If you want to receive infos emails, set send_infos=Yes in the config or use --infos."
            )
            should = False

        if last_wp_report is not None:
          if (
              last_wp_report["last_email"] is not None
              and datetime.strptime(wp_report["datetime"], DATE_FORMAT)
                - datetime.strptime(last_wp_report["last_email"], DATE_FORMAT)
                < self.resend_emails_after
              and last_wp_report["status"] == wp_report["status"]
          ):
              # No report notice
              log.info(
                  f"Not sending WPWatcher {wp_report['status']} email report for site {wp_report['site']} because already sent in the last {self.resend_emails_after}."
              )
              should = False

        return should

    def send_report(
        self, wp_site: Dict[str, Any], wp_report: Dict[str, Any], wpscan_command: str
    ) -> bool:
        """Sending the report"""
        # Send the report to
        if len(self.email_errors_to) > 0 and wp_report["status"] == "ERROR":
            to = self.email_errors_to
        else:
            to = wp_site["email_to"] + self.email_to

        if not to:
            log.info(
                f"Not sending WPWatcher {wp_report['status']} email report because no email is configured for site {wp_report['site']}"
            )
            return False

        while self._mail_lock.locked():
            time.sleep(0.01)

        with self._mail_lock:
            self._send_report(wp_report, to, wpscan_command)
            return True

    @staticmethod
    def build_message(wp_report: Dict[str, Any], wpscan_command: str) -> str:
        """Build mail message text base on report and warnngs and info switch"""

        message = (
            f"<p>WordPress security scan report for site: {wp_report['site']}<br />\n"
        )
        message += f"Scan datetime: {wp_report['datetime']}<br />\n<p>"

        message += format_results(wp_report, format="html")

        if wp_report["fixed"]:
            message += "<br/>\n"
            message += format_issues("Fixed", wp_report["fixed"], format="html")

        return TEMPLATE_EMAIL.substitute(
            content=message,
            wpwatcher_version=__version__,
            wpscan_command=wpscan_command,
        )


TEMPLATE_EMAIL = Template(
    """
<!doctype html>
<html>
  <head>
    <meta name="viewport" content="width=device-width">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Simple Transactional Email</title>
    <style>
    /* -------------------------------------
        INLINED WITH htmlemail.io/inline
    ------------------------------------- */
    /* -------------------------------------
        RESPONSIVE AND MOBILE FRIENDLY STYLES
    ------------------------------------- */
    @media only screen {
      table[class=body] h1 {
        font-size: 28px !important;
        margin-bottom: 10px !important;
      }
      table[class=body] p,
            table[class=body] ul,
            table[class=body] ol,
            table[class=body] td,
            table[class=body] span,
            table[class=body] a {
        font-size: 16px !important;
      }
      table[class=body] .wrapper,
            table[class=body] .article {
        padding: 10px !important;
      }
      table[class=body] .content {
        padding: 0 !important;
      }
      table[class=body] .container {
        padding: 0 !important;
        width: 100% !important;
      }
      table[class=body] .main {
        border-left-width: 0 !important;
        border-radius: 0 !important;
        border-right-width: 0 !important;
      }
      table[class=body] .btn table {
        width: 100% !important;
      }
      table[class=body] .btn a {
        width: 100% !important;
      }
      table[class=body] .img-responsive {
        height: auto !important;
        max-width: 100% !important;
        width: auto !important;
      }
    }
    /* -------------------------------------
        PRESERVE THESE STYLES IN THE HEAD
    ------------------------------------- */
    @media all {
      .ExternalClass {
        width: 100%;
      }
      .ExternalClass,
            .ExternalClass p,
            .ExternalClass span,
            .ExternalClass font,
            .ExternalClass td,
            .ExternalClass div {
        line-height: 100%;
      }
      .apple-link a {
        color: inherit !important;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        line-height: inherit !important;
        text-decoration: none !important;
      }
      #MessageViewBody a {
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
      }
      .btn-primary table td:hover {
        background-color: #34495e !important;
      }
      .btn-primary a:hover {
        background-color: #34495e !important;
        border-color: #34495e !important;
      }
    }
    </style>
  </head>
  <body class="" style="background-color: #f6f6f6; font-family: sans-serif; -webkit-font-smoothing: antialiased; font-size: 14px; line-height: 1.4; margin: 0; padding: 0; -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%;">
    <table border="0" cellpadding="0" cellspacing="0" class="body" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; background-color: #f6f6f6;">
      <tr>
        <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">&nbsp;</td>
        <td class="container" style="font-family: sans-serif; font-size: 14px; vertical-align: top; display: block; Margin: 0 auto; max-width: 800px; padding: 10px; width: 800px;">
          <div class="content" style="box-sizing: border-box; display: block; Margin: 0 auto; max-width: 1000px; padding: 10px;">
            <!-- START CENTERED WHITE CONTAINER -->
            <table class="main" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; background: #ffffff; border-radius: 3px;">
              <!-- START MAIN CONTENT AREA -->
              <tr>
                <td class="wrapper" style="font-family: sans-serif; font-size: 14px; vertical-align: top; box-sizing: border-box; padding: 20px;">
                  <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                    <tr>
                      <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">
                      <!-- START DYNAMIC CONTENT AREA -->
                      $content
                      <!-- END DYNAMIC CONTENT AREA -->
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            <!-- END MAIN CONTENT AREA -->
            </table>
            <!-- START FOOTER -->
            <div class="footer" style="clear: both; Margin-top: 10px; text-align: center; width: 100%;">
              <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                <tr>
                  <td class="content-block powered-by" style="font-family: sans-serif; vertical-align: top; padding-bottom: 10px; padding-top: 10px; font-size: 12px; color: #999999; text-align: center;">
                    WPScan command: <code> $wpscan_command </code>
                  </td>
                </tr>
                <tr>
                  <td class="content-block powered-by" style="font-family: sans-serif; vertical-align: top; padding-bottom: 10px; padding-top: 10px; font-size: 12px; color: #999999; text-align: center;">
                    Automating WPscan to scan and report vulnerable Wordpress sites <br/> 
                    <a href="https://github.com/tristanlatr/WPWatcher" style="color: #999999; text-align: center; text-decoration: none;">WPWatcher version $wpwatcher_version </a> <br />
                  </td>
                </tr>
              </table>
            </div>
            <!-- END FOOTER -->
          <!-- END CENTERED WHITE CONTAINER -->
          </div>
        </td>
        <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">&nbsp;</td>
      </tr>
    </table>
  </body>
</html>"""
)
