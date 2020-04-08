#! /usr/bin/env python3
# 
# WPWatcher reports summary generator
#
# DISCLAIMER - USE AT YOUR OWN RISK.
# 
# 
# Exemple stdin usage:
#   $ cat ~/.wpwatcher/wp_reports.json | python3 ./tools/wprs.py
#
# With param --input :
#   $ python3 ./tools/wprs.py --input ~/.wpwatcher/wp_reports.json

import json
import sys
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='WordPress reports summary')
    parser.add_argument('--input', metavar='path', help="wp_reports database file")
    args = parser.parse_args()
    return args

def results_summary(results):
    string='Results summary\n'
    header = ("Site", "Status", "Last email", "Issues", "Problematic component(s)")
    sites_w=20
    # Determine the longest width for site column
    for r in results:
        sites_w=len(r['site'])+2 if r and len(r['site'])>sites_w else sites_w
    frow="{:<%d} {:<8} {:<20} {:<8}{}"%sites_w
    string+=frow.format(*header)
    for row in results:
        pb_components=[]
        for m in row['alerts']+row['warnings']+row['errors']:
            pb_components.append(m.splitlines()[0])
        string+='\n'
        string+=frow.format(row['site'], 
            row['status'],
            str(row['last_email']),
            len(row['alerts']+row['warnings']+row['errors']),
            ', '.join(pb_components) )
    return string

if __name__ == '__main__':
    args=parse_args()
    if args.input:
        # Json parse file
        with open(args.input) as r:
            results=json.load(r)
    else:
        # Parse stdin
        lines = sys.stdin.readlines()
        for i in range(len(lines)):
            lines[i] = lines[i].replace('\n','')
        results=json.loads( '\n'.join(lines) )
        
    print(results_summary(results))