
import os
import vt
import json
from pymisp import PyMISP
from pymisp import ExpandedPyMISP, MISPEvent
import botocore
from botocore.exceptions import ClientError
import urllib3
import time
import logging
from datetime import datetime
from datetime import date
import math
import os
import virustotal3.core
import boto3
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


SLEEP_BASE = .25
misp_url = ''
misp_key = ''
API_KEY = ""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#misp = ExpandedPyMISP(misp_url, misp_key, False)
misp = ''

#
### Lists used for grabbing IOCs from MISP
#
URLsBefore = []
IPsBefore = []
DomainsBefore = []
HashesBefore = []


#
### Lists that the found IOCs from pivoting will go into
#
URLs = []
IPs = []
Domains = []
Hashes = []





def ssmClientExecutionCheck(func):
    def wrapper(*args, **kwargs):
        success = False
        error = False
        for x in range(1, 5):
            try:
                value = func(*args, **kwargs)
                success = True
            except ClientError as e:
                LOGGER.error(
                    "Error in execution for %s. Error: %s" % (func.__name__, str(e))
                )
                error = e
                time.sleep(SLEEP_BASE * x)
                continue
            break

        # If the function never executed then raise the last error found
        if not success:
            LOGGER.error(
                "Too many errors found in execution of %s. Raising error back up."
                % func.__name__
            )
            raise error
        return value

    return wrapper


def createClient():
	"""
	Creates the SSM client for obtaining parameters.
	"""
	return boto3.client("ssm", region_name="us-east-1")




@ssmClientExecutionCheck
def getURL(ssm_client):
	"""
	Obtains the URL for the MISP EC2 instance.  
	Return: string
	"""
	return ssm_client.get_parameter(
        Name="/MISP/url", WithDecryption=False
    )["Parameter"]["Value"]

@ssmClientExecutionCheck
def getMISPKey(ssm_client):
	"""
	Obtains the key for the MISP instance.
	Return: string
	"""
	return ssm_client.get_parameter(
        Name="/MISP/key", WithDecryption=True
    )["Parameter"]["Value"]

@ssmClientExecutionCheck
def getVTKEY(ssm_client):
	"""
	Obtains a VT API key.
	Return: string
	"""
	return ssm_client.get_parameter(
        Name="/MISP/vt", WithDecryption=True
    )["Parameter"]["Value"]


def getIPs(IOC):
	"""
	Takes Hash and returns list of contacted malicious IPs

	Params: string - IOC
	returns: list of IPs 
	"""
	global IPs;
	try:
		relationship = virustotal3.core.Files(API_KEY).get_relationship(IOC, 'contacted_ips')
		attributes = relationship[list(relationship.keys())[0]]
	except:
		attributes = []
	for item in attributes:
		try:
			stats = item.get("attributes").get("last_analysis_stats")
			ID = item.get("id")
			malicious = stats.get("malicious")
			if malicious != 0:
				IPs.append(item.get("id"))
		except:
			continue


def getDomains(IOC):
	"""
	Takes Hash and returns list of contacted malicious Domains

	Params: string - IOC
	returns: list of IPs 
	"""
	global Domains;
	try:
		relationship = virustotal3.core.Files(API_KEY).get_relationship(IOC, 'contacted_domains')
		attributes = relationship[list(relationship.keys())[0]]
	except:
		attributes = []
	for item in attributes:
		try:
			stats = item.get("attributes").get("last_analysis_stats")
			ID = item.get("id")
			malicious = stats.get("malicious")
			if malicious != 0:
				Domains.append(item.get("id"))
		except:
			continue


def getURLs(IOC):
	"""
	Takes Hash and returns list of contacted malicious URLs

	Params: string - IOC
	returns: list of IPs 
	"""
	global URLs;
	try:
		relationship = virustotal3.core.Files(API_KEY).get_relationship(IOC, 'contacted_urls')
		attributes = relationship[list(relationship.keys())[0]]
	except:
		attributes = []
	for item in attributes:
		try:
			stats = item.get("attributes").get("last_analysis_stats")
			ID = item.get("id")
			malicious = stats.get("malicious")
			if malicious != 0:
				URLs.append(item.get("id"))
		except:
			continue



def getExecutionParents(IOC):
	"""
	Takes Hash and returns list of execution parents

	Params: string - IOC
	returns: list of hashes
	"""
	global Hashes;
	try:
		relationship = virustotal3.core.Files(API_KEY).get_relationship(IOC, 'execution_parents')
		attributes = relationship[list(relationship.keys())[0]]
	except:
		attributes = []
	for item in attributes:
		try:
			stats = item.get("attributes").get("last_analysis_stats")
			ID = item.get("id")
			malicious = stats.get("malicious")
			if malicious != 0:
				Hashes.append(item.get("id"))
		except:
			continue


def getPeResourceParents(IOC):
	"""
	Takes Hash and returns list of execution parents

	Params: string - IOC
	returns: list of hashes
	"""
	global Hashes;
	try:
		relationship = virustotal3.core.Files(API_KEY).get_relationship(IOC, 'pe_resource_parents')
		attributes = relationship[list(relationship.keys())[0]]
	except:
		attributes = []
	for item in attributes:
		try:
			stats = item.get("attributes").get("last_analysis_stats")
			ID = item.get("id")
			malicious = stats.get("malicious")
			if malicious != 0:
				Hashes.append(item.get("id"))
		except:
			continue

def getCompressedParents(IOC):
	"""
	Takes Hash and returns list of execution parents

	Params: string - IOC
	returns: list of hashes
	"""
	global Hashes;
	try:
		relationship = virustotal3.core.Files(API_KEY).get_relationship(IOC, 'compressed_parents')
		attributes = relationship[list(relationship.keys())[0]]
	except:
		attributes = []
	for item in attributes:
		try:
			stats = item.get("attributes").get("last_analysis_stats")
			ID = item.get("id")
			malicious = stats.get("malicious")
			if malicious != 0:
				Hashes.append(item.get("id"))
		except:
			continue


def getID(month, day, hour):
	"""
	Determines the next ID to obtain from MISP based on
	the current time.  Will need to be modified every month.

	Even days: Returns IDs ending in 0-4
	Odd days: Returns IDs ending in 5-9

	"""
	if(int(day/2) < math.ceil(day/2)):
		hour = hour + 5


	return (hour + int(math.floor(day/2) * 5) + (month * 10))



def lambda_handler(event, context):
	#Grabbing the IOCs from MISP
	global Hashes;
	global URLs;
	global IPs;
	global ID;
	global misp_url;
	global misp_key;
	global API_KEY;
	global misp;
	client = createClient()
	misp_url = getURL(client)
	misp_key = getMISPKey(client)
	API_KEY = getVTKEY(client)
	misp = ExpandedPyMISP(misp_url, misp_key, False)
	today = date.today()
	month = int(today.strftime("%m"))
	day = int(today.strftime("%d"))
	time = datetime.now()
	hour = int(time.strftime("%H"))
	ID = getID(month, day, hour)
	LOGGER.info("Event ID: " + str(ID))
	dictionary = misp.get_event(ID).get("Event")

	#f = open("MISPIOCs.txt", "w")
	for item in dictionary["Attribute"]:
		typ = item.get("type")
		value = item.get("value")
		if "sha256" in typ:
			HashesBefore.append(value.rstrip())
		elif "ip" in typ:
			IPsBefore.append(value.rstrip())
		elif "domain" in typ:
			DomainsBefore.append(value.rstrip())
		elif "URL" in typ:
			URLsBefore.append(value.rstrip())


	LOGGER.info("Hashes obtained: ")
	LOGGER.info(HashesBefore)



	# Go Through VT and obtain the relative IOCs for each IOC from MISP
	for item in HashesBefore:
		getDomains(item)
		getURLs(item)
		getExecutionParents(item)
		getIPs(item)
		getPeResourceParents(item)
		getCompressedParents(item)

	for item in DomainsBefore:
		getDomains(item)
		getURLs(item)
		getExecutionParents(item)
		getIPs(item)
		getPeResourceParents(item)
		getCompressedParents(item)

	for item in IPsBefore:
		getDomains(item)
		getURLs(item)
		getExecutionParents(item)
		getIPs(item)
		getPeResourceParents(item)
		getCompressedParents(item)




	# Write the IOCs to the file
	f = open("/tmp/newIOCs.txt", "w")
	f.write("IPs: " + "\n")
	global IPs;
	global Domains;
	global Hashes;
	for item in IPs:
		f.write(item + "\n")
	f.write("Domains: " + "\n")
	for item in Domains:
		f.write(item + "\n")
	f.write("Hashes: " + "\n")
	for item in Hashes:
		f.write(item + "\n")
	f.close()


	#Write the IOCs from the file back to MISP
	try:
		f = open("/tmp/newIOCs.txt")
		lst = f.readlines()


	finally:
	    f.close()

	IPs = False
	Hashes = False
	Domains = False
	idSafe = 1

	for item in lst:
		if item.find("IPs:") != -1:
			IPs = True
			Hashes = False
			Domains = False

	    #Set Domain Flag Check
		elif item.find("Domains:") != -1:
		    Domains = True
		    IPs = False
		    Hashes = False

		#Set Hashes Flag Check
		elif item.find("Hashes:") != -1:
		    Domains = False
		    IPs = False
		    Hashes = True
		    
		#IP attribute check
		elif IPs and item.find("IPs:") == -1:
			event = misp.add_attribute(ID, {'type': "ip-src", 'value': item.rstrip(), 'Tag': [{'id': '166', 'name': 'VT Pivot', 'colour': '#8a00ba', 'exportable': True, 'user_id': '0', 'hide_tag': False, 'numerical_value': None}]}, pythonify=True)

		    
		#Domain attribute check
		elif Domains and item.find("Domains:") == -1:
			event = misp.add_attribute(ID, {'type': "domain", 'value': item.rstrip(), 'Tag': [{'id': '166', 'name': 'VT Pivot', 'colour': '#8a00ba', 'exportable': True, 'user_id': '0', 'hide_tag': False, 'numerical_value': None}]}, pythonify=True)


		#Hash attribute check
		elif Hashes and item.find("Hashes:") == -1:
			event = misp.add_attribute(ID, {'type': "sha256", 'value': item.rstrip(), 'Tag': [{'id': '166', 'name': 'VT Pivot', 'colour': '#8a00ba', 'exportable': True, 'user_id': '0', 'hide_tag': False, 'numerical_value': None}]}, pythonify=True)





if __name__ == "__main__":

    class ContextFake:
        """This is a fake class used to populate the context method"""

        log_stream_name = "TESTING CODE"
        pass

    context = ContextFake()
    LOGGER.addHandler(logging.StreamHandler())
    LOGGER.setLevel(logging.INFO)
    event = {
        
    }
    lambda_handler(event, context)