#!/usr/bin/env python3

# Gets unique docker images from Elasticsearch API which are pulled from Shodan.

from elasticsearch import Elasticsearch, RequestsHttpConnection
import re
import argparse
import socket

es_client = Elasticsearch(host="192.168.1.7",
                            port=9200,
                            connection_class=RequestsHttpConnection)
def get_args():
    global args
    parser = argparse.ArgumentParser(description="CLI tool dump")
    parser.add_argument("--dump", action="store_true", help="Full image")

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

def separate(image):
    analytics_result = dict()
    testResult = True
    # Filter out reg_repo, service_name, version
    sep_image = re.match(r"((?P<reg_repo>(^[^/]+)(/[^/]+)?)/)?(?P<service_name>[^:]+)(:(?P<version>.+))?", image)
    if sep_image.group("version") is None:
        image = image + ":latest"
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
            # Separate registry and port
            sep_registry = re.match(r"(?P<registry>[^:]+)(:(?P<reg_port>.+))?$", true_registry)
            # Use registry and port for test
            if sep_registry:
                if sep_registry.group("reg_port"):
                    port = int(sep_registry.group("reg_port"))
                else:
                    port=80
                # Test registry port
                if not true_registry in reg_arr_scanned and not (sep_registry.group("registry").startswith('10.') or sep_registry.group("registry").startswith('172.') or sep_registry.group("registry").startswith('192.')):
                    if args.dump:
                        print(image)
                    reg_arr_scanned.append(true_registry)
                    testResult = testPort(sep_registry.group("registry"), port)
                    # If scan failed
                    if testResult != True:
                        pass
                    # If scan was success
                    else:
                        analytics_result['registry'] = true_registry
                        analytics_result['repository'] = true_repository
                # Registry already tested
                elif true_registry in reg_arr_scanned:
                    analytics_result['registry'] = true_registry
                    analytics_result['repository'] = true_repository
                else:
                    testResult = False
                    #pass
        # Registry do not exist
        else:
            sep_repository = re.match(r"(((?P<registry>^[^/]+)/)?)(?P<repository>.*)", sep_image.group("reg_repo"))
            analytics_result['registry'] = None
            analytics_result['repository'] = sep_repository.group("repository")
    # Registry and Repository do not exist
    else:
        analytics_result['registry'] = None
        analytics_result['repository'] = None

    if testResult == True:
        image_array.append(image)
        #print(image,analytics_result)
        analytics_result['service_name'] = (sep_image.group("service_name"))
        analytics_result['version'] = (sep_image.group("version"))
        if analytics_result['registry'] is not None:
            reg_arr.append(analytics_result['registry'])
        if analytics_result['repository'] is not None:
            rep_arr.append(analytics_result['repository'])
        if analytics_result['service_name'] is not None:
            ser_arr.append(analytics_result['service_name'])
        if analytics_result['version'] is not None:
            ver_arr.append(analytics_result['version'])

    return image_array,reg_arr,rep_arr,ser_arr,ver_arr

def main():
    global images

    args = get_args()

    doc = {
        'size' : 10,
        'query': {
            'match_all': {}
       }
   }
    res = es_client.search(index='shodan-docker*', filter_path=['hits.hits._source.docker.Containers','hits.hits._source.ip_str'], body=doc)

    # Print image and ip_str
    global image_array
    image_array = []
    ip_array = []

    # For analytics
    global reg_arr,rep_arr,ser_arr,ver_arr,reg_arr_scanned
    reg_arr = []
    rep_arr = []
    ser_arr = []
    ver_arr = []

    reg_arr_scanned = []
    for target in res['hits']['hits']:
        if 'docker' in target['_source']:
            if target['_source']['docker']['Containers']:
                for container in target['_source']['docker']['Containers']:
                    analytics_result = dict()
                    ip_str = target['_source']['ip_str']
                    image = container['Image']
                    docker_id = re.match(r"^(?=.*[0-9])([a-z0-9]){12}$", image)
                    if "sha256" not in image:
                        if docker_id is None:
                            image_array,reg_arr,rep_arr,ser_arr,ver_arr = separate(image)
                            #image_array.append(image)
                            ip_array.append(ip_str)
    # Separate unique images
    images = sorted(set(image_array))

    if args.dump:
        ips = sorted(set(ip_array))
        registries = sorted(set(reg_arr))
        repositories = sorted(set(rep_arr))
        services = sorted(set(ser_arr))
        versions = sorted(set(ver_arr))

        print("Total IPs")
        print (ips)
        print("REGISTRY")
        print (registries)
        print("REPOSITORY")
        print (repositories)
        print("SERVICE NAME")
        print (services)
        print("VERSION")
        print (versions)

        print ("Total IPs:", len(ips))
        print("Images:", len(images))
        print("Registries:", len(registries))
        print("Repositories:", len(repositories))
        print("Services:", len(services))
        print("Versions:", len(versions))
    else:
        return images
main()
