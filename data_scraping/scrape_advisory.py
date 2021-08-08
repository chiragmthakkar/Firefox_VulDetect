# Scrape the bug reports from the Mozilla Vulnerability Advisory Page
import pandas as pd
import requests
import re
import time

site_link = "https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/"

def make_query(query):
	r = requests.get(query)
	# Check for too many requests status code
	while r.status_code == 429:
		print("Waiting...")
		time.sleep(60)
		r = requests.get(query)
	return r

# Retieve CVE info
def scrape_cve(cve_id):
	# Get NVD page
	r = make_query("https://nvd.nist.gov/vuln/detail/"+cve_id)
	if r.ok:
		# Check page exists
		if "CVE ID Not Found" in r.text:
			return '-', '-', '-', '-'
		publish_date = r.text.split("Published Date:")[1].split("</span>")[0].split(">")[-1]
		try:
			cwe = "CWE-" + r.text.split("CWE-")[2].split("<")[0]
		except:
			cwe = '-'
		# Get CVSS2 Severity
		severity = r.text.split('class="label label-')[-1].split('</a>')[0].split('>')[1]
		# Determine affected versions
		versions = []
		if "cpe:2.3:a:mozilla:firefox:" not in r.text:
			versions = '-'
		else:
			for i in range(len(r.text.split("cpe:2.3:a:mozilla:firefox:"))-1):
				cpe = r.text.split("cpe:2.3:a:mozilla:firefox:")[i+1]
				# Check if list has ended
				if r.text.split("cpe:2.3:a:mozilla:firefox:")[i][-1] == '*':
					break
				# Check if single version
				if cpe.split(':')[0] != '*':
					versions.append(cpe.split(':')[0])
				else:
					# Else many versions
					cpe = cpe.split('rangeStartType')[0]
					if 'versions up to (excluding) ' in cpe:
						versions.append('<' + cpe.split('versions up to (excluding) ')[1].split()[0])
					if 'versions up to (including) ' in cpe:
						versions.append('<=' + cpe.split('versions up to (including) ')[1].split()[0])
			# Check for redundancy
			if versions[0] == '0.1' and '<' in versions[-1]:
				versions = [versions[-1]]
			versions = ','.join(versions)
		return publish_date, cwe, severity, versions
	return '-', '-', '-', '-'

# Scrape each advisory page for bug reports
def scrape_page(version, link):
	# Store the results
	df = pd.DataFrame(columns=['Fixed in', 'Bug Report', 'CVE ID', 'Advisory Impact', 'Announced', 'Description', 'NVD Publish Date', 'CWE', 'CVSS2 Severity', 'Affected Versions'])
	# Make the query
	r = make_query(link)
	if r.ok:
		announced = r.text.split('<dt>Announced</dt>')[1].split('</dd>')[0].split('<dd>')[1]
		# Check bug reports exist
		if '<h4 id="' not in r.text:
			# If page uses old formatting (<= release 48)
			if '<h3>References</h3>' in r.text and '<a href="https://bugzilla.mozilla.org/' in r.text:
				description = r.text.split('<h3>Description</h3>')[1].split('<p>')[1].split('</p>')[0]
				impact = r.text.split('<dt>Impact</dt>')[1].split('</span></dd>')[0].split('>')[-1]
				reffs = r.text.split('<h3>References</h3>')[1]
				for c, u in enumerate(reffs.split('<ul>')):
					if c == 0: continue
					refs = u.split('</ul>')[0]
					for d, l in enumerate(refs.split('href="https://bugzilla.mozilla.org/')):
						if d == 0: continue	# Skip the first split
						report = "https://bugzilla.mozilla.org/" + l.split('"')[0]
						cve = l.split('</a>)</li>')[0].split('>')[-1]
						publish_date, cwe, severity, affected_versions = scrape_cve(cve)
						df.at[len(df)] = [version, report, cve, impact, announced, description, publish_date, cwe, severity, affected_versions]
			else:
				return df
		for c, i in enumerate(r.text.split('<h4 id="')):
			if c == 0:	continue # Skip the first split
			cve = i.split('"')[0]
			description = i.split('<p>')[1].split('</p>')[0]
			impact = i.split('<dt>Impact</dt>')[1].split('</span></dd>')[0].split('>')[-1]
			refs = i.split('<ul>')[1].split('</ul>')[0]
			reports = []
			for d, l in enumerate(refs.split('<li><a href="')):
				if d == 0: continue	# Skip the first split
				reports.append(l.split('"')[0])
			publish_date, cwe, severity, affected_versions = scrape_cve(cve)
			df.at[len(df)] = [version, ', '.join(reports), cve, impact, announced, description, publish_date, cwe, severity, affected_versions]
	# print(df)
	return df

# Scrape the Mozilla Firefox Security Advisory
def scrape_data():
	# Store the results
	df = pd.DataFrame()
	# Make the query
	r = make_query(site_link)
	# Get advisory page links
	links = {}
	if r.ok:
		for c, i in enumerate(r.text.split('<h3 id="')):
			if c == 0:	continue # Skip the first split
			version = i.split('"')[0]
			# if int(version[7:9]) > 23: continue
			# if int(version[7:9]) == 22: break
			links[version] = []
			for d, j in enumerate(i.split("</ul>")[0].split('<li class="level-item"><a href="')):
				if d == 0:	continue # Skip the first split
				links[version].append('https://www.mozilla.org' + j.split('"')[0])
	# Scrape the data
	for v, v_links in links.items():
		print(v)
		for l in v_links:
			data = scrape_page(v, l)
			df = pd.concat([df, data]).reset_index(drop=True)
	# Save the results
	df.to_csv("data/advisory_data.csv", index=False)

if __name__ == '__main__':
	scrape_data()
	exit()
