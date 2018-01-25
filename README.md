# ossec-configuration
Configuration files for deploying OSSEC in client/server configuration and integrating with the ELK stack

## Software on each server
This setup requires three types of servers: servers being monitored by an OSSEC client, an OSSEC server, and an Elasticsearch & Kibana server.

Included in this repo are Ansible playbooks for setting up OSSEC clients and an OSSEC server

### OSSEC Server
This server will have OSSEC server and Logstash running on it.  OSSEC server will stream its syslog output to Logstash, and Logstash will parse the syslog output into a data structure and ship the data structure to Elasticsearch.

The OSSEC server should have `/var/ossec/bin/ossec-authd` running in the background to register new OSSEC client nodes as they come online.

### Elasticsearch
This is just your basic Elasticsearch server with Kibana running on it as well.  Preferably have a reverse proxy setup on this to password protect Elasticsearch's ports.


