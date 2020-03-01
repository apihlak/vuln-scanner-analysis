#!/usr/bin/env python3

# Pulling images from docker repositories. Image list is from print_collected_images script.
# View images with command "docker images"
# Scan images

import print_collected_images
import docker
from multiprocessing.pool import ThreadPool as Pool
import re
import subprocess

def pull(image):
    try:
        client.images.get(image)
        print ("Image exists:", image)
    except docker.errors.ImageNotFound as e:
        print(e)
        try:
            print("Pulling image")

            client.images.pull(image)

            print("Image pull done!")
        except Exception as e:
            print("Cannot pull image:", e)

def main():
    global client
    client = docker.from_env()

    pool_size = 20
    pool = Pool(pool_size)
    
    for image in print_images.images:
        #print(image)
        pool.apply_async(pull, (image,))
        
    pool.close()
    pool.join()

if __name__ == '__main__':
    main()
