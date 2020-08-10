import unittest
from wpwatcher.parser import parse_results

class T(unittest.TestCase):
    
       def test_parser(self):
              # false positives
              out = open("tests/static/wordpress_no_vuln.json").read()
              messages, warnings, alerts=parse_results(out)
              self.assertEqual(0, len(alerts))

              out = open("tests/static/wordpress_one_vuln.json").read()
              messages, warnings, alerts=parse_results(out)
              self.assertEqual(4, len(warnings))

              out = open("tests/static/wordpress_many_vuln.json").read()
              messages, warnings, alerts=parse_results(out)
              self.assertEqual(1, len(alerts))

              out = open("tests/static/wordpress_no_vuln.txt").read()
              messages, warnings, alerts=parse_results(out)
              self.assertEqual(0, len(alerts))

              out = open("tests/static/wordpress_one_warning.txt").read()
              messages, warnings, alerts=parse_results(out)
              self.assertEqual(2, len(warnings))

              out = open("tests/static/wordpress_many_vuln.txt").read()
              messages, warnings, alerts=parse_results(out)
              self.assertEqual(8, len(alerts))
              
              out = open("tests/static/wordpress_one_vuln.txt").read()
              messages, warnings, alerts=parse_results(out)
              self.assertEqual(1, len(alerts))

       def test_false_positives(self):
              pass

       def test_version_could_not_be_detected_warning(self): 
              pass

       def test_version_could_not_be_detected_false_positive_mgmt(self): 
              pass

       def test_oudated_plugin_or_theme_version_warning(self):
              pass

       def test_vulnerabilities(self):
              pass

       def test_insecure_wordpress_warning(self):
              pass

       def test_password_attack(self):
              pass

       def test_lots_of_enumeration(self):
              pass

       def test_ref_metasploit_cve_exploitdb(self):
              pass