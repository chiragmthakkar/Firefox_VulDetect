# -*- coding: utf-8 -*-
"""diffExtractor.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1021FboN_zV6ATI4Jc3Aew9ckjxssORfu
"""

import requests
from bs4 import BeautifulSoup
from pandas.io.html import read_html
import pandas as pd
import re
from tqdm import tqdm


df = pd.read_excel(r'1_620_till_M_v64_labelData.xlsx')

df['RemovedCode'] = ""

# Initiliasing the dictionary for uniqueBugs with False (is Visited?)

# Get all the bug id's from the bug report labelled data
ll = len(df['Bug Report'])
tempList = []
for i in range(ll):
  # extracting the bug id from the bug report
  ff= df['Bug Report'][i].split('?id=')
  tempList.append(ff[1])

# Get the unique bugs from the list.
uniqueBugs = list(set(tempList))
uniqueBugsDict = dict.fromkeys(uniqueBugs,"False")

# Create a empty dataframe
colNames = ['FixedIn','BugNumber','FileName','RemovedCode','startNo','endNo']
newdf = pd.DataFrame(columns=list(colNames))

c = 0
ll = len(df['Bug Report'])

for i in tqdm(range(210,298)):
  print("Reading row ",i)

  # extracting the bug id from the bug report
  ff = df['Bug Report'][i].split('?id=')
  
  # If the bug is visited once we mark it as True (Visited)
  if uniqueBugsDict[ff[1]] == "False":
    uniqueBugsDict[ff[1]] = "True"
    c = c+1

    # Empty dictonary to keep a track of visted files for a given bug
    fileVisitDict = {}

    # creating the search query
    query = 'https://hg.mozilla.org/releases/mozilla-release/log?rev=Bug+'+ff[1]
    # print(query)
    response = requests.get(query)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    revRes = soup.findAll('div',{'class':['log_link']})
    for rrValue in revRes:
      l = rrValue.find('a', href=True)['href']
      link = 'https://hg.mozilla.org/'+l
      hash = re.split(r'/rev/',link)
      queryb = "https://hg.mozilla.org//releases/mozilla-release/rev/"+hash[1]

      responseB = requests.get(queryb)
      soupN = BeautifulSoup(responseB.text, 'html.parser')
      resu = soupN.findAll("td", {'class':['link']})


      for r in resu:
        l = r.findAll('a', href=True)

        for value in l:
          if re.search('/diff/',value['href']):
            linkValue = value['href']
            base = 'https://hg.mozilla.org/'
            linkFormed = base+linkValue

            
            result = linkFormed.find(hash[1])
            fileNameExt = linkFormed[result+len(hash[1])+1:len(linkFormed)]

            # Checking if the file is a cpp, cc or c extension
            if linkFormed.endswith('.cpp') or linkFormed.endswith('.cc') or linkFormed.endswith('.c') :
              if fileNameExt in fileVisitDict.keys():
                print("File:", fileNameExt ," is already present")
              else:
                print("New file: ", fileNameExt ," found! Extracting removed code...")
                fileVisitDict[fileNameExt] = "True"
                print("Diff: ",linkFormed)
                responseDiffUrl = requests.get(linkFormed)
                soupDiffUrl = BeautifulSoup(responseDiffUrl.text, 'html.parser')

                # Get the deleted code from the given URL
                resDiffUrlMinus = soupDiffUrl.findAll("span", {'class':['difflineminus']})

                # Initializing empty list, string and variables
                prev = 0
                curr = 0
                prevText = ""
                diffData = []
                store = ""
                lineNo = ""

                for value in resDiffUrlMinus:
                  # Getting the line nuber at which there is a code removed

                  prevSplit = value.get('id').split('.')
                  curr = prevSplit[1]

                  currText = value.text
                  
                  # since the 1st character is '-', we dont consider it
                  currText = currText[1:len(currText)]

                  # if the code belongs to the deleted block, there will be difference of 1 between the line numbers
                  if int(curr)-int(prev) == 1:
                    
                    # concatenate the entry
                    store = store + currText
                    lineNo = lineNo +" "+ str(curr)
                    # if the 1st line is the removed block
                    if (int(curr) == 1):

                      diffData.append([[lineNo],[store]])
                    else:
                      # remove the last entry and append the concatenated entry
                      diffData.pop()
                      diffData.append([[lineNo],[store]])

                  # if the code is a single line deletion
                  else:
                    lineNo = ""
                    lineNo = lineNo +" "+ str(curr)
                    diffData.append([[lineNo],[currText]])
                    store = currText
                    prev = 0
                  prev = curr

                print("Appending removed code in the database for Bug Id: ",df['Bug Report'][i])
                diffData = diffData[1:]
                for entry in range(len(diffData)):
                  cleanString = diffData[entry][0][0].strip(' ').split(' ')
                  start = cleanString[0]
                  if len(cleanString) == 0:
                    end = start
                  else:
                    end = cleanString[len(cleanString)-1]
                  newdf= newdf.append({'FixedIn':df['Fixed in'][i],'BugNumber': df['Bug Report'][i],'FileName':fileNameExt,'RemovedCode': diffData[entry][1][0], 'startNo': start , 'endNo':end },ignore_index=True)

newdf.to_csv('removedCode_210_298.csv')

