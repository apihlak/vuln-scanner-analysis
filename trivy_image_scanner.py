#!/usr/bin/env python3

# Prerequisite is Docker socket in localhost
# If Elasticsearch port anwers then data is to the ES otherwise output is in stdout
# Example:
# sudo ./trivy_image_scanner.py --image=ubuntu:16.04

import sys
import os
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

def migrate(image, rand):
    if not os.path.exists("/tmp/images/"):
        os.mkdir("/tmp/images/")

    tar_image = image.save()
    tar_file = f'/tmp/images/{rand}.tar'
    f = open(tar_file, 'wb')
    for chunk in tar_image:
        f.write(chunk)
    f.close()

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
    result['vulnerability'] = vulnerability
    return result

def ship_to_es(data,client,rand):

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
    severity_array = []
    try:
        for vulnerability in data['Vulnerabilities']:
            result = (parser(data,vulnerability))

            # Add image vulnerability severity count
            severity = vulnerability['Severity']
            severity_array.append(severity)
            keys = Counter(severity_array).keys()
            values = Counter(severity_array).values()

            entries_to_push.append({"_index": "<audit-images-trivy-{now/w{YYYY.ww}}>", "_source": result})
    except:
        print(f'No vulnerabilities - {args.image}')
        exit()

    severity_data = {}
    severity_data['@timestamp'] = result['@timestamp']
    severity_data['image'] = result['image']
    severity_data['registry'] = result['registry']
    severity_data['repository'] = result['repository']
    severity_data['service_name'] = result['service_name']
    severity_data['version'] = result['version']
    severity_data['message'] = "Image severity"
    severity_data['severity'] = dict(zip(keys, values))
    entries_to_push.append({"_index": "<audit-images-trivy-{now/w{YYYY.ww}}>", "_source": severity_data})

    if not (es_client.indices.exists(index="<audit-images-trivy-{now/w{YYYY.ww}}>")):
        es_client.indices.create(index="<audit-images-trivy-{now/w{YYYY.ww}}>", body=templates)
    if len(entries_to_push) > 0:
        helpers.bulk(es_client, entries_to_push)
    print("Successfully sent bulk of {} messages to Elasticsearch".format(len(entries_to_push)))

def main():
    args = get_args()
    rand=str(uuid.uuid4())
    client = docker.from_env(timeout=180)

    print(args.image)
    images = client.images.list(args.image)
    for image in images:
        print(f'Starting with {args.image}-{rand}')
        migrate(image, rand)
        # Scan Image and output result in json
        try:
            scan_output = client.containers.run(image="aquasec/trivy", volumes={'/var/run/docker.sock': {'bind': '/var/run/docker.sock', 'mode': 'ro'}, '/tmp/.cache/': {'bind': '/root/.cache/', 'mode': 'rw'}, '/tmp/images/': {'bind': '/tmp/images/', 'mode': 'ro'}}, auto_remove=True, command=f'-f json -q --skip-update --input /tmp/images/{rand}.tar').decode('utf-8')
        except:
            print(f'Unknown OS - {args.image}')
            exit()
        os.remove(f'/tmp/images/{rand}.tar')
        if scan_output[-1] != ']':
            scan_output = (f'{scan_output}]')
        else:
            scan_output
        scan_outputs = json.loads(scan_output)

        # If Elasticsearch port answers then send to ES otherwise print to stdout
        testResult = testPort(args.es_host, args.es_port)
        for scan_output in scan_outputs:
            if testResult == True:
                ship_to_es(scan_output, client, rand)
            else:
                print(scan_output)

if __name__ == '__main__':
    main()
