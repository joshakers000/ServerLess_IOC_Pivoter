# ServerLess_IOC_Pivoter
A python-based project for obtaining new IOCs from VirusTotal's API and storing within MISP.  Original IOCs are pulled from MISP and pivoted on based on their relationships.  


Makefile is not included as this is meant to pull a zipfile with all code from S3.  

Account-IDs and bucketnames have been removed.  

# Requirements

- MISP Database
- API keys stored within SSM
  - MISP
  - VirusTotal

