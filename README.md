## udp_scan.py

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
