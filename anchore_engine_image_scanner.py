#!/usr/bin/env python3

# Scans already pulled images to Docker daemon. Used for analysis.

# Prerequisite is Docker socket in localhost
# If Elasticsearch port anwers then data is to the ES otherwise output is in stdout
# Example:
# sudo ./anchore_engine_image_scanner.py --install
# sudo ./anchore_engine_image_scanner.py

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
    parser.add_argument("--install", action="store_true", help="Install Anchore-Engine Containers")
    
    group = parser.add_mutually_exclusive_group(required=False)
    parser.add_argument("--es-username", type=str, help="Elasticsearch username")
    parser.add_argument("--es-password", type=str, help="Elasticsearch password")

    parser.add_argument("--image", type=str, default="alpine:latest", help="Image to check, default is \"alpine\"")

    parser.add_argument("--es-host", default="192.168.1.7", type=str, help="Elasticsearch host")
    parser.add_argument("--es-port", default=9200, type=int, help="Elasticsearch host")

    args = parser.parse_args()

    return args

def simple_tar(path):
    f = tempfile.NamedTemporaryFile()
    t = tarfile.open(mode='w', fileobj=f)

    abs_path = os.path.abspath(path)
    t.add(abs_path, arcname=os.path.basename(path), recursive=False)

    t.close()
    f.seek(0)
    return f

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

def cleanup(image, rand, anchore_api):
    os.remove(f'/tmp/{rand}.tar')
    anchore_api.exec_run(f'rm /home/anchore/{rand}.tar')
    anchore_api.exec_run(f'rm /home/anchore/{rand}.tgz')

def parser(image, vulnerability):
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
    result = dict()
    result['@timestamp'] = timestamp
    result['image'] = image
    result['registry'] = registry
    result['repository'] = repository
    result['service_name'] = service_name
    result['version'] = version
    result['vulnerability'] = vulnerability
    return result

def migrate(image, rand, anchore_api):
    tar_image = image.save()
    tar_file = f'/tmp/{rand}.tar'
    f = open(tar_file, 'wb')
    for chunk in tar_image:
        f.write(chunk)
    f.close()

    os.chown(tar_file, 1000, 1000);
    anchore_api.put_archive("/home/anchore", simple_tar(tar_file))

def scan(image, rand, anchore_api, sha):

    # Parse image name
    analyzer = anchore_api.exec_run(f'anchore-manager analyzers exec --tag {image} --account-id admin --digest {sha} /home/anchore/{rand}.tar /home/anchore/{rand}.tgz')
    import_image = anchore_api.exec_run(f'curl -u admin:foobar -F archive_file=@/home/anchore/{rand}.tgz http://localhost:8228/v1/import/images')

def ship_to_es(data, client, rand, image):

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
    for vulnerability in data['vulnerabilities']:
        result = (parser(image ,vulnerability))

        # Add image vulnerability severity count
        severity = vulnerability['severity']
        severity_array.append(severity)
        keys = Counter(severity_array).keys()
        values = Counter(severity_array).values()

        entries_to_push.append({"_index": "<audit-images-anchore-{now/w{YYYY.ww}}>", "_source": result})

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
        entries_to_push.append({"_index": "<audit-images-anchore-{now/w{YYYY.ww}}>", "_source": severity_data})
    except:
        print("No vulnerabilities")
        pass

    if not (es_client.indices.exists(index="<audit-images-anchore-{now/w{YYYY.ww}}>")):
        es_client.indices.create(index="<audit-images-anchore-{now/w{YYYY.ww}}>", body=templates)
    if len(entries_to_push) > 0:
        helpers.bulk(es_client, entries_to_push)
    print("Successfully sent bulk of {} messages to Elasticsearch".format(len(entries_to_push)))

def main():
    args = get_args()
    client = docker.from_env(timeout=120)

    if args.install:
        try:
            client.networks.get("anchore")
        except:
            client.networks.create("anchore", driver="bridge")
        # Install Anchore Engine containers
        try:
            client.containers.get('anchore-db')
        except NotFound as e:
            print("Starting anchore-db container")
            client.containers.run(image="anchore/engine-db-preload:latest", name="anchore-db", network="anchore", detach=True, environment=["POSTGRES_PASSWORD=mysecretpassword"])
        try:
            client.containers.get('anchore-simpleq')
        except NotFound as e:
            print("Starting anchore-simpleq container")
            client.containers.run(image="anchore/anchore-engine:latest", name="anchore-simpleq", network="anchore", detach=True, environment=["ANCHORE_ENDPOINT_HOSTNAME=anchore-simpleq","ANCHORE_DB_HOST=anchore-db","ANCHORE_DB_PASSWORD=mysecretpassword","ANCHORE_LOG_LEVEL=INFO"], command="anchore-manager service start simplequeue")
        try:
            client.containers.get('anchore-catalog')
        except NotFound as e:
            print("Starting anchore-catalog container")
            client.containers.run(image="anchore/anchore-engine:latest", name="anchore-catalog", network="anchore", detach=True, environment=["ANCHORE_ENDPOINT_HOSTNAME=anchore-catalog","ANCHORE_DB_HOST=anchore-db","ANCHORE_DB_PASSWORD=mysecretpassword","ANCHORE_LOG_LEVEL=INFO"], command="anchore-manager service start catalog")
        try:
            client.containers.get('anchore-policy-engine')
        except NotFound as e:
            print("Starting anchore-policy-engine container")
            client.containers.run(image="anchore/anchore-engine:latest", name="anchore-policy-engine", network="anchore", detach=True, environment=["ANCHORE_ENDPOINT_HOSTNAME=anchore-policy-engine","ANCHORE_DB_HOST=anchore-db","ANCHORE_DB_PASSWORD=mysecretpassword","ANCHORE_LOG_LEVEL=INFO"], command="anchore-manager service start policy_engine")
        try:
            client.containers.get('anchore-analyzer')
        except NotFound as e:
            print("Starting anchore-analyzer container")
            client.containers.run(image="anchore/anchore-engine:latest", name="anchore-analyzer", network="anchore", detach=True, environment=["ANCHORE_ENDPOINT_HOSTNAME=anchore-analyzer","ANCHORE_DB_HOST=anchore-db","ANCHORE_DB_PASSWORD=mysecretpassword","ANCHORE_LOG_LEVEL=INFO"], command="anchore-manager service start analyzer")
        try:
            client.containers.get('anchore-api')
        except NotFound as e:
            print("Starting anchore-api container")
            client.containers.run(image="anchore/anchore-engine:latest", name="anchore-api", network="anchore", detach=True, ports={'8228/tcp':'8228/tcp'}, environment=["ANCHORE_ENDPOINT_HOSTNAME=anchore-api","ANCHORE_DB_HOST=anchore-db","ANCHORE_DB_PASSWORD=mysecretpassword","ANCHORE_LOG_LEVEL=INFO"], command="anchore-manager service start apiext")
        exit()

    anchore_api = client.containers.get('anchore-api')
    done_images = json.loads(anchore_api.exec_run(f'anchore-cli --json image list').output.decode('utf-8'))
    done_list = []
    for done_sha in done_images:
        done_list.append(done_sha['imageDigest'])
    images = client.images.list(args.image)
    for image in images:
        rand=str(uuid.uuid4())
        #anchore_api.exec_run("anchore-cli --json system wait")
        print(args.image)
        test_image = anchore_api.exec_run(f'anchore-cli --json image get localbuild/{args.image}').output.decode('utf-8')
        if "image data not found in DB" not in test_image:
            print(f'Image: {args.image} exists')
            data = json.loads(anchore_api.exec_run(f'anchore-cli --json image vuln localbuild/{args.image} all').output.decode('utf-8'))
        else:
            migrate(image, rand, anchore_api)
            sha = json.loads(anchore_api.exec_run(f'skopeo inspect docker-archive:/home/anchore/{rand}.tar').output.decode('utf-8'))['Digest']
            if sha in done_list:
                print(f'Image layer already exists - {args.image}')
            else:
                print(f'Scan image: {args.image}')
                scan(args.image, rand, anchore_api, sha)
            data = json.loads(anchore_api.exec_run(f'anchore-cli --json image vuln {sha} all').output.decode('utf-8'))
            cleanup(args.image, rand, anchore_api)
        if "could not fetch vulnerabilities" in str(data):
            print("Could not fetch vulnerabilities!")
        else:
            # If Elasticsearch port answers then send to ES otherwise print to stdout
            testResult = testPort(args.es_host, args.es_port)
            if testResult == True:
                print(f'Ship to es - {args.image}')
                ship_to_es(data, client, rand, args.image)
            else:
                print(data)

if __name__ == '__main__':
    main()
