# Dependency-Track Fortify SSC Bridge API

Capabilities:
* Upload project bom file to Fortify SSC
* Sync analysis state of Dependency-Track project to Fortify SSC
* Create Fortify SSC application and version if not exist

## Setup
Create a "CIToken" at Fortify SSC  
Create an API Key at Dependency-Track  
Change environment variables in docker-compose.yaml file  
Start Dependency-Track Fortify SSC Bridge API  
Create a "Outbound Webhook" alert at Dependency-Track  
