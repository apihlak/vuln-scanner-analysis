#!/usr/bin/env python3

# Prerequisite is Docker socket in localhost
# If Elasticsearch port anwers then data is to the ES otherwise output is in stdout
# Example:
# sudo ./clair_image_scanner.py --install
# sudo ./clair_image_scanner.py --image=ubuntu:16.04

import sys
import docker
from docker.errors import NotFound
import uuid
import json
import datetime
import time
import re
import argparse
import socket
from collections import Counter
import base64
from pathlib import Path

from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers

def get_args():
    global args
    parser = argparse.ArgumentParser(description="CLI tool to scan images")
    parser.add_argument("--install", action="store_true", help="Install Clair Containers")
    
    group = parser.add_mutually_exclusive_group(required=False)
    parser.add_argument("--es-username", type=str, help="Elasticsearch username")
    parser.add_argument("--es-password", type=str, help="Elasticsearch password")

    parser.add_argument("--image", type=str, default="alpine:latest", help="Image to check, default is \"alpine\"")
    parser.add_argument("--host", type=str, default="https://index.docker.io/v1/", help="Docker private registry")

    parser.add_argument("--es-host", default="192.168.1.7", type=str, help="Elasticsearch host")
    parser.add_argument("--es-port", default=9200, type=int, help="Elasticsearch host")

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

def scan(client,rand):
    '''
    Pull image and scan. Save output to container clair-scanner /tmp directory
    '''
    try:
        container = client.containers.get('clair-scanner')
    except NotFound as e:
        print ("Missing Clair Container | use --install"); exit()
    image = str(args.image)
    container.exec_run(['sh', '-c', 'clair-scanner --reportAll=False --ip=$(hostname -i | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+") --clair=http://172.17.0.1:6060 --report=/tmp/{0}-scan {1}'.format(rand, image)])

def parser(data,vulnerability):
    sep_image = re.match(r"((?P<reg_repo>(^[^/]+)(/[^/]+)?)/)?(?P<service_name>[^:]+)(:(?P<version>.+))?", data['image'])
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
    result['image'] = data['image']
    result['registry'] = registry
    result['repository'] = repository
    result['service_name'] = service_name
    result['version'] = version
    result['vulnerability'] = vulnerability
    return result

def ship_to_es(log, client, rand):

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

    entries_to_push = []
    data = json.loads(log)
    severity_array = []
    for vulnerability in data['vulnerabilities']:
        result = (parser(data,vulnerability))

        # Add image vulnerability severity count
        severity = vulnerability['severity']
        severity_array.append(severity)
        keys = Counter(severity_array).keys()
        values = Counter(severity_array).values()

        entries_to_push.append({"_index": "<audit-images-clair-{now/w{YYYY.ww}}>", "_source": result})

    try:
        severity_data = {}
        severity_data['@timestamp'] = result['@timestamp']
        severity_data['image'] = result['image']
        severity_data['registry'] = result['registry']
        severity_data['repository'] = result['repository']
        severity_data['service_name'] = result['service_name']
        severity_data['version'] = result['version']
        severity_data['message'] = "Image severity"
        severity_data['severity'] = dict(zip(keys, values))
        entries_to_push.append({"_index": "<audit-images-clair-{now/w{YYYY.ww}}>", "_source": severity_data})
    except:
        print(f'No vulnerabilities - {args.image}')
        client.containers.get('clair-scanner').exec_run('rm /tmp/{0}-scan'.format(rand))
        exit()

    if not (es_client.indices.exists(index="<audit-images-clair-{now/w{YYYY.ww}}>")):
        es_client.indices.create(index="<audit-images-clair-{now/w{YYYY.ww}}>", body=templates)
    if len(entries_to_push) > 0:
        helpers.bulk(es_client, entries_to_push)
    print("Successfully sent bulk of {} messages to Elasticsearch".format(len(entries_to_push)))

    client.containers.get('clair-scanner').exec_run('rm /tmp/{0}-scan'.format(rand))

def main():
    args = get_args()
    rand=str(uuid.uuid4())
    client = docker.from_env()

    if args.install:
        # Install Clair containers
        try:
            client.containers.get('clair-db')
        except NotFound as e:
            print("Starting clair-db container")
            client.containers.run(image="arminc/clair-db:latest", name="clair-db", detach=True, ports={'5432/tcp':'5432/tcp'})
        try:
            client.containers.get('clair-local-scan')
        except NotFound as e:
            print("Starting clair-local-scan container")
            client.containers.run(image="arminc/clair-local-scan:latest", name="clair-local-scan", detach=True, ports={'6060/tcp':'6060/tcp'}, links={'clair-db':'postgres'})
        try:
            client.containers.get('clair-scanner')
        except NotFound as e:
            print("Starting clair-scanner container")
            client.containers.run(image="ovotech/clair-scanner:latest", name="clair-scanner", detach=True, volumes={'/var/run/docker.sock': {'bind': '/var/run/docker.sock', 'mode': 'ro'}}, command="tail -f /dev/null")
        exit()

    # Scan image
    scan(client,rand)

    # Output of scan result in json
    scan_output = client.containers.get('clair-scanner').exec_run('cat /tmp/{0}-scan'.format(rand)).output.decode('utf-8')
    if "No such file or directory" in scan_output:
        print(f'ERROR: Clair did not scan - tmp file missing {args.image}    {rand}')
        exit()
    # If Elasticsearch port answers then send to ES otherwise print to stdout
    testResult = testPort(args.es_host, args.es_port)
    if testResult == True:
        ship_to_es(scan_output, client, rand)
    else:
        print(scan_output)
        client.containers.get('clair-scanner').exec_run('rm /tmp/{0}-scan'.format(rand))
       
if __name__ == '__main__':
    main()
