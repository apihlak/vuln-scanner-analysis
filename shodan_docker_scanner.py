#!/usr/bin/env python3

# Gets open Docker engine ports from Shodan API

# sudo pip3 install shodan elasticsearch

import shodan
import socket
import os
from datetime import date, datetime
from elasticsearch import Elasticsearch, RequestsHttpConnection, ElasticsearchException, helpers
from elasticsearch.helpers import bulk

API_KEY="<SHODAN-API-KEY>"
# Setup the api
api = shodan.Shodan(API_KEY)

es_client = Elasticsearch(host="192.168.1.7",
                            port=9200,
                            connection_class=RequestsHttpConnection)


def sendES(entries_to_push,counter):
    templates = '''
    {
      "settings": {
        "index.number_of_shards": 1,
        "index.number_of_replicas": 0,
        "index.mapping.total_fields.limit": 6000,
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

    if not (es_client.indices.exists(index="<shodan-docker-{now/d}>")):
        es_client.indices.create(index="<shodan-docker-{now/d}>", body=templates)
    try:
        helpers.bulk(es_client, entries_to_push)
        print("Pushed ", counter, " logs")
    except Exception as e:
        print(str(e))
        pass

def testPort(ip,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        return True
    except:
        return False
    finally:
        s.close()

def printIP(query,port):
    result = api.search(query, page=x)
    # Loop through the matches and print each IP
    entries_to_push = []
    counter=0
    for service in result['matches']:
        try:
            result = testPort(service['ip_str'], int(port))
            if result == True:
                service['@timestamp'] = service['timestamp']
                log_date = datetime.strptime(service['timestamp'], '%Y-%m-%dT%H:%M:%S.%f').strftime('%d/%m/%Y')
                
                try:
                    del service['ssl']['cert']['serial']
                except Exception:
                    pass
                try:
                    del service['docker']['BuildTime']
                except Exception:
                    pass
                try:
                    for component in service['docker']['Components']:
                        try:
                            del component['Details']['BuildTime']
                        except Exception:
                            pass
                except Exception:
                    pass

                try:
                    container_count=0
                    for container in service['docker']['Containers']:
                        try:
                            del container['Labels']
                        except Exception:
                            pass
                        try:
                            del container['NetworkSettings']
                        except Exception:
                            pass
                        try:
                            service[container_count] = container['Image']
                            container_count+=1
                        except Exception as e:
                            print(str(e))
                            pass
                except Exception:
                    pass
                
                if log_date >= last_date:
                    entries_to_push.append({"_index": "<shodan-docker-{now/d}>", "_source": service})
                    counter+=1
                    print(counter)
        except Exception:
            pass
    sendES(entries_to_push,counter)
                
def referenceDate():
    global last_date
    if os.path.isfile("/tmp/last_date"):
        last_date = open("/tmp/last_date", 'r').read()
    else:
        today = date.today().strftime("%d/%m/%Y")
        last_date = open("/tmp/last_date", 'w')
        last_date.write(str(today))
        last_date.close()
        last_date = open("/tmp/last_date", 'r').read()
        
    # Return All Data
    #last_date="01/01/2019"
    return " after:"+ last_date

def main():
    ports = ["2376", "2375"]
    for port in ports:
        # Perform the search
        query = 'port:' + port + ' product:Docker' + referenceDate()
            # If API key do not support after function
            # query = 'port:' + port + ' product:Docker'
            # referenceDate()
        print(query)
        total_count = api.count(query)
        if total_count['total'] > 100:
            nr=int(total_count['total']/100)
        else:
            nr=1
        
        print("Docker daemon port:", port, " total IP count:",total_count['total'], " total shodan pages:",nr)
        
        global x 
        for x in range(1,nr+1):
            for attempt in range(5):
                try:
                    print(x,"- page")
                    printIP(query,port)
                except shodan.APIError as e: 
                    print(str(e))
                    continue
                else:
                    break
            else:
                print("Timeout. Skip page:",x)
    today = date.today().strftime("%d/%m/%Y")
    last_date = open("/tmp/last_date", 'w')
    last_date.write(str(today))
if __name__ == '__main__':
    main()
