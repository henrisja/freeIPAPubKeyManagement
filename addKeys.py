#!/usr/bin/env python

##################################################################################
#                                                                                #
# Script to manage sshPublicKeys. Performs LDAP query against domain specified   #
# in the config file and then adds any users with sshPublicKeys to the list      #
# of userID overrides on the freeIPA side to allow ssh key login to any machines #
# managed by freeIPA.                                                            #
#                                                                                #
##################################################################################

import keyConfig as cfg
import os
arr = cfg.ADCreds['domain'].split('.')
temp = ""

#######################################################################
#                                                                     #
# Break up the domain name into component dc sections for LDAP Querry #
#                                                                     #
#######################################################################

i = 0
while i < len(arr):
 temp+="dc="
 temp+=arr[i]
 if i+1 < len(arr):
   temp+=","
 i+=1

#####################################################################
#                                                                   #
# Issue shell command to perform LDAP lookup of users with SSH keys #
# and pipe output to a temporary file                               #
#                                                                   #
#####################################################################

ldapQuery = "ldapsearch -x -h " + cfg.ADCreds['dc'] + " -D " + cfg.ADCreds['user'] + " -W -b " + temp +  " -s sub '(sshPublicKeys=*)' sshPublicKeys userPrincipalName > temp.txt"
os.system(ldapQuery)

############################################################################
#                                                                          #
# Parse the temp file and store user principal names and associated        #
# sshPublicKeys in an array. Need to remove extraneous spaces and new line #
# characters from the response sshPubKey string.                           #
#                                                                          #
############################################################################

accounts = []
file = open("temp.txt", "r")
count = 0
sshString = ""
for line in file:
  if "userPrincipalName:" in line:
    accounts.append(line.split(": ")[1].rstrip())
  if "sshPublicKeys:" in line or count > 0:
    if count == 0:
      sshString = line.split(": ")[1].rstrip()
    else:
      sshString+=line.split(" ",1)[1].rstrip()
    count+=1
    if count == 6:
      count = 0
      accounts.append(sshString)
      sshString=""
file.close()
os.system('rm temp.txt')

########################################################################################
#                                                                                      #
# Need to receive admin kerberos credentials in order to modify freeIPA user overrides #
# Pass through the array of UPN and sshPubKeys and issue command line command to       #
# add them to the list of user overrides. If user already has an override it checks    #
# for a difference in the sshPubKeys and replaces if necessary. In the event a sshKey  #
# will be replaced the sssd cache for that user must be purged or else authentication  #
# will be against out of date key                                                      #
#                                                                                      #
########################################################################################

os.system('kinit admin')
i = 0
while i < len(accounts):
  findAccount = "ipa idoverrideuser-find \"Default Trust View\" --desc=" + accounts[i] + " > temp.txt" 
  os.system(findAccount)
  file = open("temp.txt", "r")
  lines = file.readlines()
  if "1 User" in lines[1]: 
    existingKey = lines[5].split(": ")[1].rstrip()
    if accounts[i+1] != existingKey:
      ipaCommand ="ipa idoverrideuser-mod \"Default Trust View\" " + accounts[i] + " --sshpubkey=\"" + accounts[i+1] + "\""
      os.system(ipaCommand)
      sssdClearUser = "sudo sss_cache -u " + accounts[i]
      os.system(sssdClearUser)
  else:
    ipaCommand = "ipa idoverrideuser-add \"Default Trust View\" " + accounts[i] + " --desc=" + accounts[i] + " --sshpubkey=\"" + accounts[i+1] + "\""
    os.system(ipaCommand)
  file.close()
  i+=2
  os.system('rm temp.txt')








