## udp_scan
- Generate bash-script to scan your infrastructure
- Get probes.go file for [udpx](https://github.com/nullt3r/udpx/tree/main) project
- Get nmap-payloads from all collected probes
- Get nmap-payloads for specific rarity, according to [nmap-service-probes](https://svn.nmap.org/nmap/nmap-service-probes) file

About file `./udp_scan/ports`:\
You may use the file from this repository or set only ports of your interest. For example, leave only port `443` in that file.


About file `./udp_scan/targets/TARGETS`:\
It's a folder, where your scope should lie. For example, it might look like this:
```
333.333.333.333/32
444.444.444.444/16
555.555.555.555/24
etc
```


About folder `./udp_scan/results`:\
After launching the generated script, the results will be written right to that folder.


Usage:
```
Help:
        python3 udp_scan.py [PARAM] [OPTIONS]

To generate script to scan with ZMAP:
        python3 udp_scan.py --generate-scan zmap

To generate script to scan with MASSCAN:
        python3 udp_scan.py --generate-scan masscan

To generate file with probes in UDPX format:
        python3 udp_scan.py --get-probes udpx

To generate file with probes in NMAP-PAYLOADS format:
        python3 udp_scan.py --get-probes nmap-payloads

To generate file with probes in NMAP-PAYLOADS format with exact RARITY:
        python3 udp_scan.py --get-probes nmap-payloads 1
```


## amplificat0r

Put results of scan into `./amlificat0r/results` and run `amplificat0r.py`:
```
Usage:
        python3 amplificat0r.py [MODE] [LIMIT]

To check scope for IPs who show looped behavior, responding over 100 times: 
        python3 amplificat0r.py --looped-ips 100

To check scope for IPs who have responded with banners, bigger than 1000 bytes: 
        python3 amplificat0r.py --big-banners 1000
```


## nmap-service-probes_udp_only_recasted
It's a recasted by CyberOK version of file [nmap-service-probes](https://svn.nmap.org/nmap/nmap-service-probes). Some ports added to probes and rarities of some probes are incremented. The list of recasts is mentioned at the beginning of the file. You can use it with nmap or use it with `udp_scan/udp_scan.py` tool. To use this file with `udp_scan.py` tool, just put it into `./udp_scan` folder and rename to `nmap-service-probes`. 
