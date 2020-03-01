#!/usr/bin/env python3

# Scan already pulled images. Used for Analysis.

import print_collected_images
import docker
from multiprocessing.pool import ThreadPool as Pool
import re
import subprocess

def scan_clair(image):
    print("Scan:", image)
    command = "python3 clair_image_scanner.py --image=" + image
    output = subprocess.check_output(['bash', '-c', command])
    print (output)

def scan_trivy(image):
    print("Scan:", image)
    command = "python3 trivy_image_scanner.py --image=" + image
    output = subprocess.check_output(['bash', '-c', command])
    print (output)

def scan_anchore_engine(image):
    print("Scan:", image)
    command = "python3 anchore_engine_image_scanner.py --image=" + image
    output = subprocess.check_output(['bash', '-c', command])
    print (output)

def scan_dagda(image):
    print("Scan:", image)
    #command = f'python3 dagda_image_scanner.py --image={image}'
    command = f'python3 dagda_image_scanner.py --image={image} --vuln'
    output = subprocess.check_output(['bash', '-c', command])
    print (output)

def scan():
    pool_size = 3
    pool = Pool(pool_size)
    image_count=[]
  
    pulled_images = client.images.list()
    images_name = re.findall(r'\'(.*?)\'', str(pulled_images))

    images_name = [string for string in sorted(images_name) if string != ""]
    for image in images_name:
        # Exclude scanning tools
        if "clair" in str(image) or "anchore" in str(image) or "dagda" in str(image) or "trivy" in str(image) or "falco" in str(image) or "clamav" in str(image):
            pass
        else:
            print(image)
            image_count.append(image)
            pool.apply_async(scan_clair, (image,))
            pool.apply_async(scan_trivy, (image,))
            pool.apply_async(scan_anchore_engine, (image,))
            pool.apply_async(scan_dagda, (image,))
    pool.close()
    pool.join()
    
    print("Scanned images:",len(image_count))

def main():
    global client
    client = docker.from_env()

    scan()

if __name__ == '__main__':
    main()
