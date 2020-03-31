#!/usr/bin/env python3

# Prerequisite is Docker socket in localhost
# If Elasticsearch port anwers then data is to the ES otherwise output is in stdout
# Example:
# sudo ./image_scanner.py --image=ubuntu:16.04 --severity HIGH,CRITICAL --enforce

import os
import os.path
import sys
import docker
import json
import datetime
import time
import re
import argparse
import socket
from collections import Counter
from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers

def get_args():
    global args
    parser = argparse.ArgumentParser(description="Trivy Scanner CLI tool to scan images")
    parser.add_argument("--image", type=str, required=True ,help="Image to check, ex. \"alpine:latest\"")
    parser.add_argument("--enforce", action="store_true", help="Set exit code to 1 (error). Default 0")
    parser.add_argument("--severity", type=str, default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", help="severities of vulnerabilities to be displayed (comma separated) (default: \"UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL\")")
    parser.add_argument("--es-host", default="192.168.1.7", type=str, help="Elasticsearch host")
    parser.add_argument("--es-port", default=9200, type=int, help="Elasticsearch port")

    parser.add_argument("--es-username", type=str, help="Elasticsearch username")
    parser.add_argument("--es-password", type=str, help="Elasticsearch password")
    
    args = parser.parse_args()
    return args

def testPort(host,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, port))
        return True
    except:
        return False
    finally:
        s.close()

def parser(data,vulnerability):
    sep_image = re.match(r"((?P<reg_repo>(^[^/]+)(/[^/]+)?)/)?(?P<service_name>[^:]+)(:(?P<version>.+))?", args.image)
    # Registry or repo exists
    if sep_image.group("reg_repo"):
        # Filter out IP and URL
        reg_repo_filter =  re.match("(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*)|.*(:).*|(.*\.co)|(.*\.io)|(.*\.cn)", sep_image.group("reg_repo"))
        # Registry exist
        if reg_repo_filter:
            # Filter registry and repository
            sep_repository = re.match(r"(((?P<registry>^[^/]+)/)?)(?P<repository>.*)", reg_repo_filter.group())
            # Find true registry
            if sep_repository.group("registry") is None:
                true_registry = sep_repository.group("repository")
                repo = re.match(r"(((?P<registry>^[^/]+)/)?)(?P<repository>.*)", sep_image.group("reg_repo"))
                repo_match = re.match("(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*)|.*(:).*|(.*\.co)|(.*\.io)|(.*\.cn)", repo.group("repository"))
                if repo_match is None:
                    true_repository = repo.group("repository")
                else:
                    true_repository = None
            else:
                true_registry = sep_repository.group("registry")
                true_repository = sep_repository.group("repository")
            registry = true_registry
            repository = true_repository
            service_name = sep_image.group("service_name")
            version = sep_image.group("version")
        else:
            registry = None
            repository = sep_image.group("reg_repo")
            service_name = sep_image.group("service_name")
            version = sep_image.group("version")
    else:
        registry = None
        repository = sep_image.group("reg_repo")
        service_name = sep_image.group("service_name")
        version = sep_image.group("version")

    timestamp = datetime.datetime.fromtimestamp(datetime.datetime.utcnow().timestamp()).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    result = dict()
    result['@timestamp'] = timestamp
    result['image'] = args.image
    result['registry'] = registry
    result['repository'] = repository
    result['service_name'] = service_name
    result['version'] = version
    result['target'] = data['Target']
    try:
        result['OS'] = re.search(" \((?P<OS>.*)\)$", data["Target"]).group("OS")
    except:
        result['OS'] = None
    result['vulnerability'] = vulnerability
    return result

def ship_to_es(entries_to_push):

    templates = '''
    {
      "settings": {
        "index.number_of_shards": 1,
        "index.number_of_replicas": 0,
        "index.mapping.total_fields.limit": 5000,
        "index.refresh_interval": "5s"
      },
      "mappings" : {
          "properties" : {
            "@timestamp": { "type": "date"},
            "@version": { "type": "keyword"},
            "geoip"  : {
              "dynamic": true,
              "properties" : {
                "ip": { "type": "ip" },
                "location" : { "type" : "geo_point" },
                "latitude" : { "type" : "half_float" },
                "longitude" : { "type" : "half_float" }
              }
            }
          }
        }
      }
    }'''

    es_client = Elasticsearch(host=args.es_host,
                            port=args.es_port,
                            connection_class=RequestsHttpConnection,
                            timeout=60)
    if args.es_username:
        es_client = Elasticsearch(host=args.es_host,
                            port=args.es_port,
                            connection_class=RequestsHttpConnection,
                            http_auth=(args.es_username, args.es_password),
                            use_ssl=True,
                            verify_ssl=True)

    if not (es_client.indices.exists(index="<audit-images-{now/w{YYYY.ww}}>")):
        es_client.indices.create(index="<audit-images-{now/w{YYYY.ww}}>", body=templates)
    if len(entries_to_push) > 0:
        helpers.bulk(es_client, entries_to_push)
    print(f'Sent bulk of {len(entries_to_push)} messages to ES - {args.image}')

def main():

    args = get_args()

    client = docker.from_env(timeout=180)

    try:
        test = client.images.get(args.image)
    except docker.errors.ImageNotFound:
        try:
            test = client.images.pull(args.image)
        except docker.errors.ImageNotFound:
            print(f'Pull access denied for {args.image}')
            exit()

    print(f'Scanning image: {args.image}')

    db_file = "/root/.cache/trivy/db/trivy.db"

    # If Elasticsearch port answers then send to ES otherwise print to stdout
    testResult = testPort(args.es_host, args.es_port)
    if testResult == True:
        o_format = "json"
    else:
        o_format = "table"
    
    if os.path.isfile(db_file) == False or (os.path.isfile(db_file) and time.time() - os.path.getctime(db_file) > 3600):
        try:
            scan_output = client.containers.run(image="aquasec/trivy:latest", volumes={'/var/run/docker.sock': {'bind': '/var/run/docker.sock', 'mode': 'ro'}, '/root/.cache/': {'bind': '/root/.cache/', 'mode': 'rw'}}, auto_remove=True, command=f'-f {o_format} --severity {args.severity} --ignorefile /root/.cache/.trivyignore -q {args.image}').decode('utf-8')
        except:
            print(f'Unknown OS {args.image}')
            exit()
    else:
        try:
            scan_output = client.containers.run(image="aquasec/trivy:latest", volumes={'/var/run/docker.sock': {'bind': '/var/run/docker.sock', 'mode': 'ro'}, '/root/.cache/': {'bind': '/root/.cache/', 'mode': 'rw'}}, auto_remove=True, command=f'-f {o_format} --severity {args.severity} --skip-update --ignorefile /root/.cache/.trivyignore -q {args.image}').decode('utf-8')
        except:
            print(f'Unknown OS {args.image}')
            exit()

    if testResult == True:

        if scan_output[-1] != ']':
            scan_outputs = json.loads(f'{scan_output}]')
        else:
            scan_outputs = json.loads(scan_output)

        for scan_output in scan_outputs:
            entries_to_push = []
            severity_array = []
            if scan_output['Vulnerabilities']:
                #os.remove(f'/root/.cache/trivy/fanal/{args.image}')
                for vulnerability in scan_output['Vulnerabilities']:
                        result = (parser(scan_output,vulnerability))
                        # # Add image vulnerability severity count
                        severity = vulnerability['Severity']
                        severity_array.append(severity)
                        keys = Counter(severity_array).keys()
                        values = Counter(severity_array).values()
                        entries_to_push.append({"_index": "<audit-images-{now/w{YYYY.ww}}>", "_source": result})
                severity_data = {}
                severity_data['@timestamp'] = result['@timestamp']
                severity_data['image'] = result['image']
                severity_data['registry'] = result['registry']
                severity_data['repository'] = result['repository']
                severity_data['service_name'] = result['service_name']
                severity_data['version'] = result['version']
                severity_data['message'] = "Image severity"
                severity_data['severity'] = dict(zip(keys, values))
                
                entries_to_push.append({"_index": "<audit-images-{now/w{YYYY.ww}}>", "_source": severity_data})
                ship_to_es(entries_to_push)
                
                if args.enforce:
                    enforce = 1
                else:
                    enforce = 0
            else:
                print(f'No vulnerabilities in {args.image}')
                enforce = 0
    else:
        enforce = 0
        print(scan_output)
    #client.images.remove(args.image)
    sys.exit(enforce)

if __name__ == '__main__':
    main()
