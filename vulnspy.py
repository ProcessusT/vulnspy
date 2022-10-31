#!/usr/bin/env python3
#
# VULNSPY
#
# V 1.1
#
# Copyright (C) 2022 Les tutos de Processus. All rights reserved.
#
#
# Description:
#   VULNSPY regularly retrieves the latest published vulnerabilities 
#    with their CVSS score and allows you to alert by email if a 
#    defined threshold is exceeded
#
# Author:
#   Processus (@ProcessusT)
# CoAuthor:
#   Vozec (@Vozec1) (Code ReWritten)


config_scraper = {
	'max_day_to_retrieve': 1,
	'max_day_limit': 5,
	'alert_score' : 7.0,
}

config_webhook = {
	'url':'https://discord.com/api/webhooks/1034XXXXXXXXXXXXXX32644/kvHdpjerEXXXXXXXXXXXXXXXXXX'
}

config_bot = {
	'token':'OTQ2ODI2ODk0NjI2NjUyMjXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
	'prefix':'!',
	'description':'VulnSpy BOT',
	'channel_id':1034839344306987123,
	'admin_id':386258192549906080
}

config_mail = {
	'recipients':['test@internet.fr', 'test2@internet.fr'],
	'smtp_login' : "vulnspy@internet.fr",
	'smtp_password' : "",
	'smtp_server' : "smtp.internet.fr",
	'smtp_port' : 25,
	'smtp_auth' : False,
	'smtp_ssl' : False,
	'smtp_tls' : False
}

config_slack = {
	"slack_token": "<SLACK_TOKEN>",
	 "channel": "<CXXXXXXXX>" 
	}

is_scraping_now = False

###########################################################################################
## BOT ####################################################################################
###########################################################################################


import discord
from discord.ext import commands

bot = commands.Bot( 
	command_prefix=config_bot['prefix'],
	description=config_bot['description'],
	help_command=None,
	intents=discord.Intents.all()
)
def check_admin(id_):
	# Check if user can use Bot
	return id_ == config_bot['admin_id']

# Split message without splitting ``` 
def discord_split(text, len_max=1500):
	if len(text) < len_max:
		return [text]
	messages,buffer,cmt,i = [],'',False,0	
	while i != len(text):
		if buffer.endswith('```'):
			cmt = not cmt
		elif len(buffer) > len_max and text[i] == '\n' and not cmt:
			messages.append(buffer)
			buffer = ''
		buffer += text[i]
		i += 1
	messages.append(buffer)
	return messages

# Get Best CVE 
def get_best_cve(cves):
	bestcve,bestcve_score = None,0.0
	for cve in cves['nist']:
		nist = cve['nist_score'] if cve['nist_score'] != "Not Provided" else '0.0'
		cna  = cve['cna_score'] if cve['cna_score'] != "Not Provided" else '0.0'
		if float(nist) > bestcve_score:
			bestcve_score,bestcve = float(nist),cve['cve']
		if float(cna) > bestcve_score:
			bestcve_score,bestcve = float(cna),cve['cve']
	return bestcve,bestcve_score

def discord_msg(CVEs):
	# Discord Message Format
	all_messages = []
	for cve in CVEs:
		# Get Best CVE
		best_cve,bestcve_score = get_best_cve(cve)

		# Is score > Minimum score
		if bestcve_score > config_scraper['alert_score']:
			message = '-'*96
			message += """\n**%s**\n\n• __Cve__: %s\n• __Date de l'alerte__: %s\n• __Alerte CERT-FR__: <%s>\n\n"""%(
				cve['title'],','.join(cve['cve']),cve['pubdate'],cve['link']
			)

			if cve['mitre'] != []:
				message += 	'• **Mitre** :\n'+'\n'.join([
						'''- Url: *<%s>*%s'''%(x['url'],'\n```\nDescription: %s\n```'%x['description'] if x['description'] != 'unknown' else '')
						for x in cve['mitre'] if best_cve in x['url']]
				)+'\n'	

			if cve['nist'] != []:
				message += '• **Nist** :\n'+'\n'.join(
					['''- Url: *<%s>*\n\n• __Score Nist__: %s\n• __Score Cna__: %s'''%(
						x['url'],x['nist_score'],x['cna_score']
					)
					for x in cve['nist']  if best_cve in x['url'] ]
				)

			message = message.strip()
			message += '\n' + '-'*96
			all_messages += discord_split(message)
	return all_messages

# Handler bot connected
@bot.event
async def on_ready():	
	print('%s has connected to Discord!\n'%bot.user.name)
	await bot.change_presence(status=discord.Status.online, activity=discord.Game(config_bot['prefix'] + 'help'))

# Help Menu
@bot.command()
async def help(ctx):
	if not check_admin(ctx.message.author.id):
		return -1
	embed = discord.Embed(title="Help Menu", description="",color=0x00ff00)
	embed.add_field(name='%srefresh max_days (int)'%config_bot['prefix'],	value='Refresh last CVE',inline=False)
	embed.add_field(name='%shelp'%config_bot['prefix'],	value='Display this menu',inline=False)
	await ctx.send(embed=embed)

# Scrape CVE
@bot.command()
async def refresh(ctx,maxday=config_scraper["max_day_to_retrieve"]):
	# Check if is_admin
	if not check_admin(ctx.message.author.id):
		return

	# Block if there is another scrape
	if is_scraping_now:
		await ctx.send('**VulnSpy is already scraping somewhere ! Please Wait**')
		return

	# Max Days provided in the command is valid ? (= isdigit)
	if not str(maxday).isdigit():
		await ctx.send('**"%s" is invalid , setting max_day. to %s**'%(
			maxday,config_scraper["max_day_to_retrieve"]))
		maxday = config_scraper["max_day_to_retrieve"]
		return

	# Max Days provided in the command is to big ? ( > 10 days => A lot of messages => Spam)
	elif maxday > config_scraper["max_day_limit"]:
		await ctx.send('**"%s" is to big ( > %s) , setting max_day. to %s**'%(
			maxday,config_scraper["max_day_limit"],config_scraper["max_day_to_retrieve"]))
		maxday = config_scraper["max_day_to_retrieve"]

	# Scrape CVE & Send 
	last_cve = scrape_all_cve(maxday)
	channel = await bot.fetch_channel(config_bot['channel_id'])
	for msg in discord_msg(last_cve):
		await channel.send(msg)

###########################################################################################
## SMTP ###################################################################################
###########################################################################################

import smtplib, ssl
from email.mime.text import MIMEText

def email_msg(cves):
	email_msg = ''.join(discord_msg(last_cve))
	to_rep = ['**','__','```']
	for x in to_rep:
		email_msg = email_msg.replace(x,'')
	return email_msg

def email_send(msg):
	try:
		context = ssl.create_default_context() if config_mail['smtp_ssl'] else None
		d1 = datetime.now().strftime("%d-%m-%Y %H:%M")
		msg = MIMEText(message)
		msg['Subject'] = "Compte-rendu alertes du CERT-FR " + str(d1)
		msg['From'] = config_mail['smtp_login']
		msg['To'] =  ','.join(config_mail['recipients'])
		with smtplib.SMTP(config_mail['smtp_server'], config_mail['smtp_port'], context=context) as server:
			if smtp_auth == True:
				server.login(config_mail['smtp_login'],config_mail['smtp_password'])
			for recipient in config_mail['recipients']:
				server.sendmail(config_mail['smtp_login'], config_mail['recipients'], msg.as_string())
	except Exception as ex:
		print('Error: %s'%ex)

###########################################################################################
## SLACK ##################################################################################
###########################################################################################

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

def slack_msg(cves):
    base_msg = "".join(discord_msg(cves))
    slack_msg = base_msg.replace("__", "_").replace("**", "*")
    return slack_msg


def slack_send(msg):
    client = WebClient(token=config_slack["slack_token"])
    try:
        response = client.chat_postMessage(channel=config_slack["channel"], text=msg)
    except SlackApiError as ex:
        print("Error: %s" % ex)

###########################################################################################
## UTILS ##################################################################################
###########################################################################################


import argparse

# Arguments Parser
def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='This tool is used to scrape last CVE published on CERT-FR')
    parser.add_argument("-b","--bot",dest="bot", action="store_true", default=False, help="Use Discord bot mode.")
    parser.add_argument("-w","--webhook",dest="webhook", action="store_true", default=False, help="Use Webhook bot mode.")
    parser.add_argument("-e","--email",dest="email", action="store_true", default=False, help="Use Email mode.")
    parser.add_argument("-s","--slack",dest="slack",action="store_true",default=False,help="Use Slack mode.")
    args = parser.parse_args()
    return args

# Send throught webhook
def webhook_send(all_msg):
	url = config_webhook['url']
	for msg in all_msg:
		try:
			data = {"content": msg}
			requests.post(url, json=data)
		except Exception as ex:
			print('Failed to send message: %s'%ex)

###########################################################################################
## SCRAPER ################################################################################
###########################################################################################

import requests
from datetime import *
import xml.etree.ElementTree as ET
import re

# Scrape CVE Number
def scrape_cve(link):
	resp = requests.get(link).text
	regex = r'cve\.mitre\.org\/cgi-bin\/cvename\.cgi\?name=(.*)">'
	return re.findall(regex,resp)

# Scrape Description + Check if CVE is Valid on Mitre.org
def scrape_mitre(CVEs):	
	def scrape_desc(cnt0):
		cnt1 = cnt0.split('<th colspan="2">Description</th>')[1]
		cnt2 = cnt1.split('<th colspan="2">References</th>')[0]
		if 'will be provided' in cnt2:
			return 'unknown'
		return re.findall(r'<td colspan="2">(.*)\n',cnt2)[0]

	valid_mitre = []
	for cve in CVEs:
		url = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s'%cve
		resp = requests.get(url).text
		if 'ERROR:' not in resp:
			valid_mitre.append({
				'cve':cve,
				'url':url,
				'description':scrape_desc(resp)
			})
	return valid_mitre	
	
# Scrape Score + Check if CVE is valid on Nist.gov
def scrape_nist(CVEs):
	def scrape_nist(cnt):
		try:	
			cnt1 = cnt.split('data-testid="vuln-cvss3-panel-score"')[1]
			return cnt1.split('</a>')[0].split('>')[1].strip().split()[0]
		except:
			return 'Not Provided'
	def scrape_cna(cnt):
		try:	
			cnt1 = cnt.split('data-testid="vuln-cvss3-cna-panel-score"')[1]
			return cnt1.split('</a>')[0].split('>')[1].strip().split()[0]
		except:
			return 'Not Provided'

	valid_nist = []
	for cve in CVEs:
		url = 'https://nvd.nist.gov/view/vuln/detail?vulnId=%s'%cve
		resp = requests.get(url).text
		if 'CVE ID Not Found' not in resp:
			valid_nist.append({
				'cve':cve,
				'url':url,
				'nist_score':scrape_nist(resp),
				'cna_score':scrape_cna(resp)
			})
	return valid_nist

# Main Function for scraping : Get All infos => Return a list of Dict with all scrapped data.
def scrape_all_cve(max_days=config_scraper['max_day_to_retrieve']):
	# Set Boolean to true => Only one per one Scrape
	global is_scraping_now
	is_scraping_now = True

	# Get all vulns
	all_cve = requests.get('https://www.cert.ssi.gouv.fr/avis/feed/').text

	# 'For all Recent Vuln in all vulns:'
	vuln 	= []
	for item in ET.fromstring(all_cve).findall('channel/item'):
		pubdate = datetime.strptime(item[2].text, "%a, %d %b %Y %H:%M:%S %z")
		if pubdate >= datetime.now(timezone.utc)+ timedelta(days=-max_days):

			# Get CVE Number
			CVEs  = scrape_cve(item[1].text)
			print('Scraping : %s'%','.join(CVEs))

			# Save All data
			vuln.append({
				'title':item[0].text,
				'link':item[1].text,
				'pubdate':item[2].text,
				'cve':CVEs,
				'mitre':scrape_mitre(CVEs), # Scrape Mitre Infos
				'nist':scrape_nist(CVEs) # Scrape Nists Infos
			})
	is_scraping_now = False
	return vuln 

###########################################################################################
###########################################################################################
###########################################################################################



def main(args):
	if args.bot == args.webhook == args.email == args.slack == False:
		print('Please specify an notification mode  (see --help) ')
		return -1

	# If bot mode => Start the bot
	if args.bot:
		bot.run(config_bot['token'])
		return 1
	else:
		# Else Scrape
		last_cve = scrape_all_cve()

		# If webhook mode => Send with webhook
		if args.webhook:
			all_msg = discord_msg(last_cve)
			webhook_send(all_msg)
			return 1

		# If email mode => Send with email
		if args.email:
			all_msg = email_msg(last_cve)
			email_send(all_msg)
			return 1

        # If slack mode => Send whith slack
		if args.slack:
			all_msg = slack_msg(last_cve)
			slack_send(all_msg)
			return 1

if __name__ == "__main__":	
	args = parse_args()
	main(args)
