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
        self.assertEqual(3, len(warnings))

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