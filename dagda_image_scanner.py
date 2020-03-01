#!/usr/bin/env python3

# Scans already pulled images to Docker daemon. Used for analysis.

# Prerequisite is Docker socket in localhost
# If Elasticsearch port anwers then data is to the ES otherwise output is in stdout
# Example:
# sudo ./dagda_image_scanner.py --install
# sudo ./dagda_image_scanner.py

import sys
import docker
from docker.errors import NotFound
import uuid
import json
import datetime
import time
import os
import re
import argparse
import socket
from collections import Counter
import base64
from pathlib import Path
import tarfile
import tempfile

from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers

def get_args():
    global args
    parser = argparse.ArgumentParser(description="CLI tool to scan images")
    parser.add_argument("--install", action="store_true", help="Install dagda-Engine Containers")
    
    group = parser.add_mutually_exclusive_group(required=False)
    parser.add_argument("--es-username", type=str, help="Elasticsearch username")
    parser.add_argument("--es-password", type=str, help="Elasticsearch password")

    parser.add_argument("--image", type=str, default="alpine:latest", help="Image to check, default is \"alpine\"")
    parser.add_argument("--vuln", action="store_true", help="Send vulns to right place")

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

def parser(image, data, vulnerability):
    sep_image = re.match(r"((?P<reg_repo>(^[^/]+)(/[^/]+)?)/)?(?P<service_name>[^:]+)(:(?P<version>.+))?", image)

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
    result = dict(data)
    for key, value in vulnerability.items():
        result['database'] = key
        for key2, value2 in value.items():
            result[key2] = value2
    result['@timestamp'] = timestamp
    result['image'] = image
    result['registry'] = registry
    result['repository'] = repository
    result['service_name'] = service_name
    result['version'] = version
    return result

def ship_to_es(data, image):

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

    # OS Vulnerabilities
    for vulnerability in data['static_analysis']['os_packages']['os_packages_details']:
        if vulnerability['vulnerabilities']:
            for vuln in vulnerability['vulnerabilities']:
                if 'os_packages_details' in str(data['static_analysis']):
                    del data['static_analysis']['os_packages']['os_packages_details']
                if 'malware_binaries' in str(data['static_analysis']):
                    del data['static_analysis']['malware_binaries']
                if 'java' in str(data['static_analysis']):
                    del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                if 'js' in str(data['static_analysis']):
                    del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                if 'nodejs' in str(data['static_analysis']):
                    del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                if 'php' in str(data['static_analysis']):
                    del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                if 'python' in str(data['static_analysis']):
                    del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                if 'ruby' in str(data['static_analysis']):
                    del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                result = (parser(image, data, vuln))
                entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    # Malware Binaries
    if 'malware_binaries' in data['static_analysis']:
        for vulnerability in data['static_analysis']['malware_binaries']:
            if vulnerability['vulnerabilities']:
                for vuln in vulnerability['vulnerabilities']:
                    if 'os_packages_details' in str(data['static_analysis']):
                        del data['static_analysis']['os_packages']['os_packages_details']
                    if 'malware_binaries' in str(data['static_analysis']):
                        del data['static_analysis']['malware_binaries']
                    if 'java' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                    if 'js' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                    if 'nodejs' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                    if 'php' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                    if 'python' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                    if 'ruby' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                    result = (parser(image, data, vuln))
                    entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    # Java
    if 'java' in data['static_analysis']['prog_lang_dependencies']['dependencies_details']:
        for vulnerability in data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']:
            if vulnerability['vulnerabilities']:
                for vuln in vulnerability['vulnerabilities']:
                    if 'os_packages_details' in str(data['static_analysis']):
                        del data['static_analysis']['os_packages']['os_packages_details']
                    if 'malware_binaries' in str(data['static_analysis']):
                        del data['static_analysis']['malware_binaries']
                    if 'java' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                    if 'js' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                    if 'nodejs' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                    if 'php' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                    if 'python' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                    if 'ruby' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                    result = (parser(image, data, vuln))
                    entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    # JS
    if 'js' in data['static_analysis']['prog_lang_dependencies']['dependencies_details']:
        for vulnerability in data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']:
            if vulnerability['vulnerabilities']:
                for vuln in vulnerability['vulnerabilities']:
                    if 'os_packages_details' in str(data['static_analysis']):
                        del data['static_analysis']['os_packages']['os_packages_details']
                    if 'malware_binaries' in str(data['static_analysis']):
                        del data['static_analysis']['malware_binaries']
                    if 'java' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                    if 'js' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                    if 'nodejs' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                    if 'php' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                    if 'python' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                    if 'ruby' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                    result = (parser(image, data, vuln))
                    entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    # nodejs
    if 'nodejs' in data['static_analysis']['prog_lang_dependencies']['dependencies_details']:
        for vulnerability in data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']:
            if vulnerability['vulnerabilities']:
                for vuln in vulnerability['vulnerabilities']:
                    if 'os_packages_details' in str(data['static_analysis']):
                        del data['static_analysis']['os_packages']['os_packages_details']
                    if 'malware_binaries' in str(data['static_analysis']):
                        del data['static_analysis']['malware_binaries']
                    if 'java' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                    if 'js' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                    if 'nodejs' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                    if 'php' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                    if 'python' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                    if 'ruby' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                    result = (parser(image, data, vuln))
                    entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    # php
    if 'php' in data['static_analysis']['prog_lang_dependencies']['dependencies_details']:
        for vulnerability in data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']:
            if vulnerability['vulnerabilities']:
                for vuln in vulnerability['vulnerabilities']:
                    if 'os_packages_details' in str(data['static_analysis']):
                        del data['static_analysis']['os_packages']['os_packages_details']
                    if 'malware_binaries' in str(data['static_analysis']):
                        del data['static_analysis']['malware_binaries']
                    if 'java' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                    if 'js' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                    if 'nodejs' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                    if 'php' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                    if 'python' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                    if 'ruby' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                    result = (parser(image, data, vuln))
                    entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    # python
    if 'python' in data['static_analysis']['prog_lang_dependencies']['dependencies_details']:
        for vulnerability in data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']:
            if vulnerability['vulnerabilities']:
                for vuln in vulnerability['vulnerabilities']:
                    if 'os_packages_details' in str(data['static_analysis']):
                        del data['static_analysis']['os_packages']['os_packages_details']
                    if 'malware_binaries' in str(data['static_analysis']):
                        del data['static_analysis']['malware_binaries']
                    if 'java' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                    if 'js' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                    if 'nodejs' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                    if 'php' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                    if 'python' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                    if 'ruby' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                    result = (parser(image, data, vuln))
                    entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    # ruby
    if 'python' in data['static_analysis']['prog_lang_dependencies']['dependencies_details']:
        for vulnerability in data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']:
            if vulnerability['vulnerabilities']:
                for vuln in vulnerability['vulnerabilities']:
                    if 'os_packages_details' in str(data['static_analysis']):
                        del data['static_analysis']['os_packages']['os_packages_details']
                    if 'malware_binaries' in str(data['static_analysis']):
                        del data['static_analysis']['malware_binaries']
                    if 'java' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['java']
                    if 'js' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['js']
                    if 'nodejs' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['nodejs']
                    if 'php' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['php']
                    if 'python' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['python']
                    if 'ruby' in str(data['static_analysis']):
                        del data['static_analysis']['prog_lang_dependencies']['dependencies_details']['ruby']
                    result = (parser(image, data, vuln))
                    entries_to_push.append({"_index": "<audit-images-dagda-{now/w{YYYY.ww}}>", "_source": result})

    if not (es_client.indices.exists(index="<audit-images-dagda-{now/w{YYYY.ww}}>")):
        es_client.indices.create(index="<audit-images-dagda-{now/w{YYYY.ww}}>", body=templates)
    if len(entries_to_push) > 0:
        helpers.bulk(es_client, entries_to_push)
    print("Successfully sent bulk of {} messages to Elasticsearch".format(len(entries_to_push)))

def main():
    args = get_args()
    client = docker.from_env(timeout=120)

    if args.install:
        try:
            client.networks.get("dagda")
        except:
            client.networks.create("dagda", driver="bridge")
        # Install Dagda containers
        try:
            client.containers.get('dagda-db')
        except NotFound as e:
            print("Starting dagda-db container")
            client.containers.run(image="mongo:latest", name="dagda-db", network="dagda", detach=True)
        try:
            client.containers.get('dagda')
        except NotFound as e:
            print("Starting dagda container")
            client.containers.run(image="3grander/dagda:0.8.0", name="dagda", network="dagda", detach=True, ports={'5000/tcp':'5000/tcp'}, environment=["DAGDA_HOST=127.0.0.1","DAGDA_PORT=5000"], volumes={'/var/run/docker.sock': {'bind': '/var/run/docker.sock', 'mode': 'ro'}}, command="start -s 0.0.0.0 -p 5000 -m dagda-db -mp 27017")
            dagda = client.containers.get('dagda')
            while testPort("172.17.0.1", 5000) == False:
                time.sleep(1)
            dagda.exec_run("python3 dagda.py vuln --init")
            init_out = "Initializing"
            while init_out != "Updated":
                init_out = json.loads(dagda.exec_run("python3 dagda.py vuln --init_status").output.decode('utf-8'))['status']
                time.sleep(2)
                print(f'{init_out} vuln database...')
        exit()

    dagda = client.containers.get('dagda')
    # Check if image is scanned already
    list_scan_image = json.loads(dagda.exec_run(f'python3 dagda.py history {args.image}').output.decode('utf-8'))
    # Check if image is scanned already
    if 'msg' in list_scan_image and list_scan_image['msg'] == "History not found":
        try:
            scan_id = json.loads(dagda.exec_run(f'python3 dagda.py check -i {args.image}').output.decode('utf-8'))['id']
        except :
            print("Something went wrong")
            exit()
        print(f'Scanning {args.image} with id: {scan_id}')
    elif list_scan_image[0]['status'] == "Completed":
        print(f'Image {args.image} scan completed')
    else:
        print(list_scan_image[0]['status'])
    if args.vuln:
        print(f'python3 dagda.py history {args.image}')
        scan_complete_array = json.loads(dagda.exec_run(f'python3 dagda.py history {args.image}').output.decode('utf-8'))
        #print(scan_complete_array)
        for scan_complete in scan_complete_array:
            if scan_complete['status'] == "Completed":
                testResult = testPort(args.es_host, args.es_port)
                #for data in scan_complete:
                if testResult == True:
                    ship_to_es(scan_complete, args.image)
                else:
                    print(scan_complete)
if __name__ == '__main__':
    main()
