# fsm_nozomi_cmdb_integration
## Importing Nozomi CMDB into FortiSIEM CMDB
This is about importing Nozomi Central Management Console CMDB into FortiSIEM CMDB via inbound integration.
The integration works via a pulling script (fetch_nozomi_cmdb.py) which runs on cron periodically to fetch CMDB data from Nozomi CMC and stores it on FortiSIEM file system as a CSV file.
FortiSIEM Inbound Integration (NozomiCSVIntegration.xml) imports the CSV file periodically to its CMDB

