#!/usr/bin/env python3
#
# VULNSPY
#
# V 1.0
#
# Copyright (C) 2022 Les tutos de Processus. All rights reserved.
#
#
# Description:
#   VULNSPY regularly retrieves the latest published vulnerabilities 
#	with their CVSS score and allows you to alert by email if a 
#	defined threshold is exceeded
#
# Author:
#   Processus (@ProcessusT)
#




# If a vulnerability CVSS score is above this variable, you will be notified
alert_score = 7.5

# vulnerabilities will be retrieved until now to "how_many_days_to_retrieve" 
how_many_days_to_retrieve = 5

# List of recipients to notified separated by coma
recipients_emails = ['test@internet.fr', 'test2@internet.fr']

# SMTP options for notifications
smtp_login = "vulnspy@internet.fr"
smtp_password = ""
smtp_server = "smtp.internet.fr"
smtp_port = 25
smtp_auth = False
smtp_ssl = False
smtp_tls = False

# Discord options for notifications
discord_token = "<DISCORD TOKEN>" 
discord_channel_id = "<DISCORD_CHANNEL>"


# In future versions we can add multiple notification type : Whatsapp, webhook... etc
notification_type = {"email", "discord"}

# for debug
debug = True





##################################################################
import sys
import smtplib, ssl
from email.mime.text import MIMEText
import xml.etree.ElementTree as ET
import urllib.request
import requests
from datetime import *
import json



# notify by email
def send_email(message):
	try:
		today = datetime.now()
		d1 = today.strftime("%d-%m-%Y %H:%M")
		msg = MIMEText(message)
		msg['Subject'] = "Compte-rendu alertes du CERT-FR " + str(d1)
		msg['From'] = smtp_login
		string_recipients = ""
		for recipient in recipients_emails:
			string_recipients = str(string_recipients) + "," + str(recipient)
		msg['To'] =  string_recipients


		if smtp_ssl == True:
			context = ssl.create_default_context()
			with smtplib.SMTP(smtp_server, smtp_port, context=context) as server:
				if debug == True:
					server.set_debuglevel(1)
				if smtp_auth == True:
					server.login(smtp_login, smtp_password)
				for recipient in recipients_emails:
					server.sendmail(smtp_login, recipients_emails, msg.as_string())
					if debug == True:
						print("Email successfully sent")
		else:
			with smtplib.SMTP(smtp_server, smtp_port) as server:
				if debug == True:
					server.set_debuglevel(1)
				if smtp_auth == True:
					server.login(smtp_login, smtp_password)
				if smtp_tls is True :
					server.starttls()
				server.sendmail(smtp_login, recipients_emails, msg.as_string())
				if debug == True:
					print("Email successfully sent")
	except Exception as e:
		print("err : " + str(e))
		pass



# notify by discord
def send_discord(message):
	try:
		import discord
		bot = discord.Client(intents=discord.Intents.default())

		# discord messages are 2000 chars max length
		array_of_msg = []
		if len(message)>1990:
			while len(message)>1990:
				array_of_msg.append(message[0:1990])
				message = message[1990:]
			array_of_msg.append(message)
		else:
			array_of_msg.append(message)

		@bot.event
		async def on_ready():
			general_channel = bot.get_channel(discord_channel_id)
			for chunk in array_of_msg:
				await general_channel.send(str(chunk))
			await bot.close()
		
		bot.run(discord_token)
	except Exception as e:
		#print(str(e))
		pass
				


# get latest vulnerabilities from CERT-FR RSS channel
def get_vulns():
	url = 'https://www.cert.ssi.gouv.fr/avis/feed/'
	response = urllib.request.urlopen(url).read()
	root = ET.fromstring(response)
	vulns = []
	for item in root.findall('channel/item'):
		try:
			item_title = item[0].text
			item_link = item[1].text
			item_pubdate = item[2].text
			item_array = [item_title, item_link, item_pubdate]
			last_three_days = datetime.now(timezone.utc)+ timedelta(days=-how_many_days_to_retrieve)
			# pubdate format is : Mon, 24 Oct 2022 11:24:13 +0000
			pubdate = datetime.strptime(item[2].text, "%a, %d %b %Y %H:%M:%S %z")
			# we don't take vuln older than last three days
			if pubdate>=last_three_days:
				vulns.append(item_array)
		except Exception as e:
			print(str(e))
			pass
	return vulns



# retrieve CVSS score on NIST website from MITRE website for each vulnerability
def get_cvss_score(vulns):
	vulns_with_score = {}
	for vuln in vulns:
		try:
			vuln_title = vuln[0]
			vuln_url = vuln[1]
			vuln_pubdate = vuln[2]
			response = urllib.request.urlopen(vuln_url).read()
			mitre_links = str(response).split("<a href=\"http://cve.mitre.org")
			i=0
			current_vuln_details = {}
			for link in mitre_links:
				i=i+1
				if "cgi-bin/cvename.cgi?name=" in link:
					link = link.split("\">", 1)[0]
					if len(link) > 6 and "DOCTYPE html" not in link:
						if debug == True:
							print("Analyzing http://cve.mitre.org" + str(link) + "...")
						nist_url = "http://cve.mitre.org"+ str(link)
						response = urllib.request.urlopen(nist_url).read()
						nist_link = str(response).split("https://nvd.nist.gov/view/vuln/detail", 1)[1]
						vuln_id = nist_link.split("\" target=\"_blank\"", 1)[0]
						nist_link = "https://nvd.nist.gov/view/vuln/detail" + str(vuln_id)
						if debug == True:
							print("Retrieved NIST link : " + str(nist_link) )
						response = urllib.request.urlopen(nist_link).read()
						nist_score = "0"
						cna_score = "0"
						try:
							nist_score = str(response).split("id=\"Cvss3NistCalculatorAnchor\"", 1)[1]
							nist_score = str(nist_score).split("</a>", 1)[0]
							nist_score = str(nist_score).split("\">", 1)[1]
						except Exception as e:
							pass
						try:
							cna_score = str(response).split("id=\"Cvss3CnaCalculatorAnchor\"", 1)[1]
							cna_score = str(cna_score).split("</a>", 1)[0]
							cna_score = str(cna_score).split("\">", 1)[1]
						except Exception as e:
							pass
						# convert to numeric value only
						# 9.8 CRITICAL => 9.8
						l_nist_score = []
						for t in nist_score.split():
							try:
								l_nist_score.append(float(t))
							except ValueError:
								pass
						l_cna_score = []
						for t in cna_score.split():
							try:
								l_cna_score.append(float(t))
							except ValueError:
								pass
						nist_score = l_nist_score[0]
						cna_score = l_cna_score[0]
						if debug == True:
							print("NIST score = "+str(nist_score))
							print("CNA score = "+str(cna_score))

						current_vuln_details[i] = {"vuln_title" : vuln_title, "vuln_url" : vuln_url, "nist_link" : nist_link, "vuln_pubdate" : vuln_pubdate, "cna_score" : cna_score, "nist_score" : nist_score}

			vuln_id = vuln_url.split("avis/")[1][:-1]
			vulns_with_score[vuln_id] = current_vuln_details
		except Exception as e:
			print('ERROR')
			print(str(e))
			pass
	return vulns_with_score






# Format a message to notify admins
def format_vulns_by_score(vulns_with_score):
	message=""
	above_alert = []
	for vuln in vulns_with_score:
		for vuln_details in vulns_with_score[vuln].values():
			if(vuln_details['cna_score']>=alert_score or vuln_details['nist_score']>=alert_score):
				if vuln not in above_alert:
					above_alert.append(vuln)
	if debug == True:
		print("Alerts with vulnerabilities above threshold : " + str(above_alert))
	classement = "------------------------------------------------------------------------------------------------\n\n\n\nAutres vulnérabilités non critiques :\n\n"
	this_one_is_done = []
	a_vuln_was_above = False
	for vuln in vulns_with_score:
		list_of_nist_links = ""
		title = ""
		max_score = 1.0
		min_score = 10.0
		pubdate = ""
		try:
			if vuln in this_one_is_done:
				break
			else:
				this_one_is_done.append(vuln)
			if vuln in above_alert:
				i = 0
				title = ""
				pubdate = ""
				for vuln_details in vulns_with_score[vuln].values():
					if i == 0:
						if a_vuln_was_above == False:
							message += "Alerte du CERT-FR comportant des vulnérabilités avec un CVSS supérieur à " + str(alert_score)+" sur les "+str(how_many_days_to_retrieve)+" dernier(s) jour(s) :\n\n\n"
							a_vuln_was_above = True
						title += "• "+ str(vuln_details['vuln_title']) + "\n\nLien vers l'alerte du CERT-FR : \n"
						title += str(vuln_details['vuln_url']) + "\n\n"
						pubdate += "Date de l'alerte : "+str(vuln_details['vuln_pubdate'])+"\n"

					if vuln_details['cna_score']<=min_score and vuln_details['cna_score']>0:
						min_score = vuln_details['cna_score']
					if vuln_details['nist_score']<=min_score and vuln_details['nist_score']>0:
						min_score = vuln_details['nist_score']
					if vuln_details['cna_score']>=max_score:
						max_score = vuln_details['cna_score']
						max_score_nist_link = vuln_details['nist_link']
					if vuln_details['nist_score']>=max_score:
						max_score = vuln_details['nist_score']
						max_score_nist_link = vuln_details['nist_link']
					i = i +1
				message += str(title) + str(pubdate) + "\nScore CVSS max : "+ str(max_score) + "\nScore CVSS min : "+ str(min_score)+"\nVulnérabilité la plus critique : " + str(max_score_nist_link) + "\n"
				message += "\n\n\n"
			else:
				i = 0
				title = ""
				pubdate = ""
				for vuln_details in vulns_with_score[vuln].values():
					if i == 0:
						title += "• "+ str(vuln_details['vuln_title']) + "\n\nLien vers l'alerte du CERT-FR : \n"
						title += str(vuln_details['vuln_url']) + "\n\n"
						pubdate += "Date de l'alerte : "+str(vuln_details['vuln_pubdate'])+"\n"
					if vuln_details['cna_score']<=min_score and vuln_details['cna_score']>0:
						min_score = vuln_details['cna_score']
					if vuln_details['nist_score']<=min_score and vuln_details['nist_score']>0:
						min_score = vuln_details['nist_score']
					if vuln_details['cna_score']>=max_score:
						max_score = vuln_details['cna_score']
					if vuln_details['nist_score']>=max_score:
						max_score = vuln_details['nist_score']
					i = i+1
				if max_score == 1:
					max_score = "NC"
				if min_score == 10:
					min_score = "NC"
				if len(title)>0 and len(pubdate)>0:
					classement += str(title) + str(pubdate) + "\nScore CVSS max : "+ str(max_score) + "\nScore CVSS min : "+ str(min_score)
					classement += "\n\n"
		except Exception as e:
			print(str(e))
			pass
	
	message += "\n\n\n" + str(classement)
	return message
					














vulns = get_vulns()

vulns_with_score = get_cvss_score( vulns ) 

message = format_vulns_by_score(vulns_with_score)

try:
	for option in notification_type:
		if option == "email":
			#send_email(message)
			print('ok')
		if option == "discord":
			send_discord(message)
except Exception as ex:
	print(str(ex))
	pass
