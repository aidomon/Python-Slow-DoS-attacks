# Python-Slow-DoS-attacks
Bachelor's thesis "Slow rate DoS attacks independent of application layer protocol".

## Table of content
1.  [Slow DoS attack generator](#Slow DoS attack generator)
    - [How to install and run the script?](#How to install and run the script?)
    - [Attack configuration](#Attack configuration)
    - [Examples of use on a web server](#Examples of use on a web server)
2. [Slow DoS Intrusion Detection System](#Slow DoS Intrusion Detection System)

# Slow DoS attack generator
Python script SlowDoSGen.py is a generator of slow DoS attacks Slowcomm and Slow Next, used to prevent service on application layer protocols. To do this, so-called sockets are used, which connect the attacker's computer with the targeted server. These attacks have 3 phases:
1. Establishing the maximum number of connections to the server using the so-called initial requests.
2. Keeping the connection active by means of so-called maintenance requirements.
3. Detection of closed connections and their replacement with new ones.
More information can be found in the bachelor thesis:
[RICHTER, Dominik. Slow rate DoS attacks independent of application layer protocol. Brno, 2020. Bachelor thesis. Brno University of Technology, Faculty of Electrical Engineering and Communication Technologies, Department of Telecommunications. Thesis supervisor Marek Sikora.](https://www.vutbr.cz/studenti/zav-prace/detail/125903)

## How to install and run the script?

Download the SlowDoSGen.py script. It is started from the command line with the `python` command
and generator names with associated parameters. Python version 3.0 and higher is required to run. To display help, execute the command:
`python3 SlowDoSGen.py -h`.

## Attack configuration

Attacks can be configured using the following parameters.

### Mandatory parameters:
- `a <str>`
This parameter is used to distinguish between individual attacks. `-a C` for Slowcomm attack
and `-a N` for Slow Next attack.
- `ip <str>`
Used to enter the destination IP address.
- `p <int>`
Used to specify the destination port.
- `c <int>`
Specifies the required number of connections to the destination.

### Optional parameters:
- `l <payload.txt>`
Used to specify your own payload using a text file, named payload.txt, in the same directory location as the generator script itself. In a Slowcomm attack, an attacker writes a request to the first line of a file. In a Slow Next attack, the attacker writes an initial request on the first line and a maintenance request on the second line. Always including line breaks, eg:
HEAD / HTTP / 1.1 \ r \ nHost: 192.168.0.155 \ r \ n \ r \ n.
- `tc <int>`
Used only in the case of a Slow Next attack. Specifies the number of threads that an attacker needs to create. The default value is 5 threads.
- `t <float>`
Specifies the timeout for sending requests - how often they are sent in a loop. The default Slowcomm attack value is 7 seconds. For Slow Next attack 3.5 seconds.
- `t2 <float>`
For Slow Next attack only. Specifies in which time interval the threads are started. The default value is 1 second.

## Examples of use on a web server

Slowcomm:
`python3 SlowDoSGen.py -a C -ip 10.10.0.2 -c 225 -p 80`
Slow Next:
`python3 SlowDoSGen.py -a N -ip 10.10.0.2 -c 140 -p 80`

# Slow DoS Intrusion Detection System

For the correct operation of the detector, it is necessary to install the mentioned Scapy library using sudo pip3 install scapy command. The program must also be run with an administrator rights using the command line with the command sudo python3 SlowDoS_IDS.py. Python 3.0 and higher is required to run. 

The program prompts the user to select one of the available interfaces on the protected server. It then obtains its IP address and stores it in the mentioned sniff filter. Further it already works automatically, it only displays a message when an attack is detected.
