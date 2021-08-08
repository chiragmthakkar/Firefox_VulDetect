# Scrape affected files of bug reports
import pandas as pd
import requests
import re
import os
import time
# Local Imports:
from scrape_advisory import scrape_cve

def make_query(query):
	r = requests.get(query)
	# Check for too many requests status code
	while r.status_code == 429:
		print("Waiting...")
		time.sleep(60)
		r = requests.get(query)
	return r

# Identify the patched files of a patch
def get_patched_files(patch):
	files = []
	# Get commit details
	try:
		r = make_query(patch)
	except:
		return []
	if r.ok:
		# Get changed files
		for l in r.text.splitlines():
			if not l.startswith('diff --git'): continue
			files.append(l.split()[2][2:])
	# Remove non C/C++ files
	files = [i for i in files if '.cpp' in i or '.c' in i]
	return files

# Scrape the data from each bug report
def scrape_report(report):
	# Get Bugzilla page
	r = make_query(report)
	if r.ok:
		# Check if allowed access
		if '<title>Access Denied</title>' in r.text:
			return 'Access Denied', '-', '-', '-', '-', '-'

		# Get the bug status
		try:
			status = ' '.join(r.text.split('<span id="field-value-status-view">')[1].split('<')[0].strip().split())
		except:
			# If there is an issue with the bug report, abort
			return '-', '-', '-', '-', '-', '-'

		# Get the recorded CVE
		if '(CVE-' in r.text:
			cve = 'CVE-' + r.text.split('(CVE-')[1].split(')')[0]
		else:
			cve = '-'

		# Get the bug severity
		bug_severity = r.text.split('<span id="field-value-bug_severity">')[1].split('<')[0].strip()

		# Get the open and closed date
		open_date = r.text.split('class="bug-time-label">Opened')[1].split('data-time="')[1].split('"')[0].strip()
		close_date = r.text.split('class="bug-time-label">Closed')[1].split('data-time="')[1].split('"')[0].strip()

		# Get the files affected by the patch(es)
		files = []
		# For each listed patch
		for i in range(len(r.text.split('<tr class=" attach-patch'))-1):
			patch = "https://bugzilla.mozilla.org" + r.text.split('<tr class=" attach-patch')[i+1].split('<a href="')[1].split('"')[0]
			# Determine type of patch
			patch_type = r.text.split('<tr class=" attach-patch')[i+1].split('<div class="attach-info">')[1].split('</div>')[0]
			if 'text/x-phabricator-request' in patch_type:	# Code Review
				# Get code review files
				s = make_query(patch)
				if s.ok:
					patch = "https://phabricator.services.mozilla.com" + s.text.split('Download Raw Diff')[0].split('<a href="')[-1].split('"')[0]
			files += get_patched_files(patch)
		# Remove duplicates
		files = ','.join(list(set(files)))
		if len(files) < 1:
			files = '-'

		return status, bug_severity, open_date, close_date, files, cve

# Scrape the data of all bug reports obtained from the security advisories
def scrape_data():
	# Load the advisory data
	df = pd.read_csv("data/advisory_data.csv")

	# Split entries, so that there is a single report per entry
	for index, row in df.iterrows():
		# Multiple links
		if ', ' in row['Bug Report']:
			for c,i in enumerate(row['Bug Report'].split(', ')):
				df.loc[index+((c+1)/100)] = row
				df.at[index+((c+1)/100), 'Bug Report'] = i
		# Multi-report
		elif ',' in row['Bug Report']:
			for c,i in enumerate(row['Bug Report'].split(',')):
				df.loc[index+((c+1)/100)] = row
				if c == 0: i = i.split('=')[1]
				df.at[index+((c+1)/100), 'Bug Report'] = 'https://bugzilla.mozilla.org/show_bug.cgi?id=' + i.strip()
		elif '%2C' in row['Bug Report']:
			for c,i in enumerate(row['Bug Report'].split('%2C')):
				df.loc[index+((c+1)/100)] = row
				if c == 0: i = i.split('=')[1]
				df.at[index+((c+1)/100), 'Bug Report'] = 'https://bugzilla.mozilla.org/show_bug.cgi?id=' + i.strip()
	df = df.sort_index().reset_index(drop=True)
	# Save the expanded complete list
	df.to_csv("data/advisory_data_ALL.csv", index=False)

	# Drop unreachable entries
	df = df[(df['Bug Report'].str.contains('https://bugzilla.mozilla.org/show_bug.cgi')) & (~df['Bug Report'].str.contains(',')) & (~df['Bug Report'].str.contains('%2C'))]

	# Add fields for bug report data
	df['Bug Status'] = '-'
	df['Bug Report Severity'] = '-'
	df['Bug Open Date'] = '-'
	df['Bug Close Date'] = '-'
	df['Affected Files'] = '-'
	# Track release
	curr_release = '-'
	# Make new dataframe for incremental storage
	df_bug = pd.DataFrame(columns=df.columns.tolist())
	# If no existing file
	if not os.path.isfile("data/bug_report_data.csv"):
		df_bug.to_csv("data/bug_report_data.csv", index=False)
	# Scrape the data of each bug report
	for index, row in df.iterrows():
		# Update Dataframe each release
		if row['Fixed in'] != curr_release:
			curr_release = row['Fixed in']
			print(curr_release)
			# Save Results so far
			df_bug.to_csv("data/bug_report_data.csv", mode='a', header=False, index=False)
			df_bug = pd.DataFrame(columns=df.columns.tolist())

		# Skip problematic versions
		try:
			if int(curr_release[7:9]) == 28 or int(curr_release[7:9]) == 21 or int(curr_release[7:9]) > 37:
				continue
		except:
			pass

		# Scrape bug report data
		status, bug_severity, open_date, close_date, files, cve = scrape_report(row['Bug Report'])
		# Add data to dataframe
		df.at[index, 'Bug Status'] = status
		df.at[index, 'Bug Report Severity'] = bug_severity
		df.at[index, 'Bug Open Date'] = open_date
		df.at[index, 'Bug Close Date'] = close_date
		df.at[index, 'Affected Files'] = files
		# Check for additional CVE data
		if cve != '-' and 'CVE-' not in row['CVE ID']:
			# Update fields
			df.at[index, 'CVE ID'] = cve
			publish_date, cwe, severity, affected_versions = scrape_cve(cve)
			df.at[index, 'NVD Publish Date'] = publish_date
			df.at[index, 'CWE'] = cwe
			df.at[index, 'CVSS2 Severity'] = severity
			df.at[index, 'Affected Versions'] = affected_versions
		df_bug.loc[len(df_bug)] = df.loc[index]

if __name__ == '__main__':
	# print(scrape_report("https://bugzilla.mozilla.org/show_bug.cgi?id=1635293"))
	scrape_data()
	exit()
