Dolos: Practical DNS Rebinding and CSRF Attack Framework
=====

Dolos provides integreated DNS and HTTP services for the purpose of demonstrating practical DNS rebinding and CSRF attacks.

Dolos is particularly well suited at targeting IoT devices thanks to two LAN enumeration techniques:
* WebRTC / STUN : Intiate a WebRTC peer data channel and then snoop on the ICE candidates. This does not work on most Safari or any IE/Edge as these platforms either do not support WebRTC or only send loopback address as an ICE candidate.
* FAINTORACLE : This is a multi-browser timing oracle based on the [JavaScript Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API). It has been tested somewhat with Chrome, Firefox, Edge, and Safari. The basic idea is that there is a side-channel in the Fetch API such that the time it takes for a request to return or error can generally reveal whether this is an active network. The timing is typically enough to tell the difference between active/inactive IPs and open/closed ports.

Deploying your own Dolos infrastructure requires a Linux server which can receive connections on a public IP address. A publicly registered domain with an NS record pointing to the Dolos server is needed to perform DNS rebinding attacks. Remember to also open UDP/53 as well as whatever ports you wish to use for HTTP. (DNS rebinding attacks require running a server on the same port as the targeted server.)

Requirements
====
* Domain name with ability to set NS record
* Python3
* [Python3 dnslib module](https://pypi.org/project/dnslib/)
* Works best with a public IP (or permissive NAT)

Configuration
====
1) Configure DNS with an NS record for some subdomain of your domain
2) Clone the sources from GitHub
3) Update dolos.conf:

| Option Name    | Description                                                |
| -------------- | ---------------------------------------------------------- |
| ns_addr        | Nameserver Address (IP or hostname)                        |
| domain         | DNS label for which Dolos is the Nameserver                |
| listen_host    | Where to bind DNS/HTTP (0.0.0.0 is generally good)         |
| http_port      | This is the default port for accepting HTTP connections.   |

Usage
====
It is recommended to run the Dolos console from within a screen session.
```
python3 dolos.py
```

The easiest way to get started using Dolos is through the GUI.

The GUI is available at http://loader.[dolos-domain]:[port]/gui

This page accepts parameters to describe a vulnerable device and supply a JavaScript payload to execute if rebinding is successful. The operator is able to supply a profile name for creating a short link of the attack profile. 

The properties of the attack profile are:
* Profile Name: This is an optional 'save name' for recalling a configuration with a short link.
* Detection Path: This is a path that responds with something other than 404 when the vulnerable targeted system receives an HTTP request.
* Request Data: Optionally supply data for including on the request when scanning for targets.
* Port Number: TCP port used by the vulnerable HTTP service
* Fetch API Network Timing Enabled: Controls how LAN is enumerated. When 'No', the FAINTORACLE technique is disabled. 'Auto' uses FAINTORACLE only if WebRTC fails. 'Yes' will force the use of FAINTORACLE even if WebRTC works (this can discover other network segmentats but at the cost of performance)
* JavaScript to run after rebinding: This is JavaScript code that will run in the context of the rebinding hostname after it has detected that rebinding was a success (based on the response from the detection request)
Attack candidates are identified by crawling discovered subnets making HTTP requests with a specified verb and path on a particular port.

When complete, the Submit button will generate the desired attack URL. If no profile name was specified, the link will contain a base64 encoding of the attack profile description.

After the victim clicks the resulting link, local network discovery is attempted. For all discovered subnets, each possible host on the subnet is sent a detection request. Hosts with an appropriate response trigger the addition of an IFRAME. The IFRAME is sourced to a ```/rebind``` URL on Dolos. This redirects to a newly generated domain name on the desired port number. This new page contains a loop to recognize when the DNS binding has changed from the Dolos server to the targeted victim. When the non-404 response is received, the JavaScript payload is executed.

Tips
====
Developing payloads is a lot easier if you point your browser to the real target (in incognito/private mode) and then open a JavaScript console. Paste the payload here and it should be pretty similar to what happens on successful rebinding.

