import os
import sys
from tqdm import tqdm


class PortProbes:
    def __init__(self, name, port, banners_in):
        self.banners = banners_in
        self.probe_name = name
        self.port = port

    def get_unique_ips(self):
        ips = []
        for i in self.banners:
            ips.append(i.split(",")[0])
        ips.sort()
        return list(set(ips))

    def count_ip_occurrences(self, ip):
        cnt = 0
        for banner in self.banners:
            if banner.split(",")[0].__eq__(ip):
                cnt += 1
        return cnt

    def get_ips_gt_n_responses(self, N):
        ips = self.get_unique_ips()
        result_ips = []
        # for ip in ips:
        for ip in tqdm(ips):
            if self.count_ip_occurrences(ip) >= N:
                result_ips.append(ip)
        return list(set(result_ips))

    def get_ips_gt_n_bytes(self, N):
        result_ips = []
        # for banner in self.banners:
        for banner in tqdm(self.banners):
            if len(banner.split(",")[2])/2 >= N:
                result_ips.append(banner.split(",")[0])
        return list(set(result_ips))


def concat_lists(list1, list2):
    for i in list2:
        list1.append(i)
    return list(set(list1))


"""
IPs responded more than N times 
For this current probe on this current port
2DO: count amplification coefficient 
"""
def count_many_responses(N: int, port_probes_array):
    for pp in port_probes_array:
        print(pp.probe_name, pp.port)
        ips_over_N_responses = pp.get_ips_gt_n_responses(N)
        if len(ips_over_N_responses) > 0:
            print(len(ips_over_N_responses), " IPs for this port:probe responded more than {} times".format(N))
            if len(ips_over_N_responses) > 0:
                print(ips_over_N_responses)
        else:
            print("nothing found")

        info_string = str(pp.probe_name) + \
                      "," + str(pp.port) + \
                      "," + str(len(ips_over_N_responses)) + \
                      "," + "{} IPs for this port:probe responded more than {} times".format(len(ips_over_N_responses), N) + \
                      "," + str(ips_over_N_responses) + "\n"
        print()
        with open("./analysis_results_many_responses", "a") as res_file:
            res_file.write(info_string)
    print("Results written to file: ./analysis_results_many_responses")


"""
2DO: count amplification coefficient
"""
def count_big_responses(B:int, port_probes_array):
    info_string = ""
    for pp in port_probes_array:
        print(pp.probe_name, pp.port)
        ips_gt_N_bytes = pp.get_ips_gt_n_bytes(B)
        if len(ips_gt_N_bytes) > 0:
            print(len(ips_gt_N_bytes), " IPs for this port:probe responded with banner > {} bytes".format(B))
        else:
            print("nothing found")
        info_string = str(pp.probe_name) + \
                       "," + str(pp.port) + \
                       "," + str(len(ips_gt_N_bytes)) + \
                       "," + "{} IPs with banners > {} bytes".format(len(ips_gt_N_bytes), B) + \
                       "," + str(ips_gt_N_bytes) + "\n"
        print()
        with open("./analysis_results_big_banners", "a") as res_file:
            res_file.write(info_string)
    print("Results written to file: ./analysis_results_big_banners")


"""
you may select PORT to analyze
if not selected, all ports will be analyzed
"""
port_to_analyze = 0
port_probes_array = []
files = os.listdir("results")
for f in files:
    if not port_to_analyze == 0 and int(f.split("-")[0]) == port_to_analyze:
        with open("results/{}".format(f), "r") as banners_results_file:
            one_file_banners = banners_results_file.readlines()
            banners = []
            for b in one_file_banners:
                if not b.__contains__("saddr"):
                    banners.append(b.replace("\n", ''))
            port_probes_array.append(PortProbes(f.split("-", 1)[1].replace(".result", ""), f.split("-")[0], banners))
    # if port is not specified, (set to 0) analysis will be performed for all files of results - may take long
    elif port_to_analyze == 0:
        with open("results/{}".format(f), "r") as banners_results_file:
            one_file_banners = banners_results_file.readlines()
            banners = []
            for b in one_file_banners:
                if not b.__contains__("saddr"):
                    banners.append(b.replace("\n", ''))
            port_probes_array.append(PortProbes(f.split("-")[1].replace(".result", ""), f.split("-")[0], banners))


def print_help():
    print("Usage:")
    print("\tpython3 amplificat0r.py [MODE] [LIMIT]")
    print()
    print("To check scope for IPs who show looped behavior, responding over 100 times: ")
    print("\tpython3 amplificat0r.py --looped-ips 100")
    print()
    print("To check scope for IPs who have responded with banners, bigger than 1000 bytes: ")
    print("\tpython3 amplificat0r.py --big-banners 1000")

########################################################################################################################


if len(sys.argv) > 2:
    parameter = sys.argv[1]
    limit = int(sys.argv[2])

    if parameter.__eq__("--help") or parameter.__eq__("-h"):
        print_help()

    if parameter.__eq__("--looped-ips") and len(sys.argv) > 2:
        count_many_responses(limit, port_probes_array)

    if parameter.__eq__("--big-banners") and len(sys.argv) > 2:
        count_big_responses(limit, port_probes_array)

    if not (parameter.__eq__("--big-banners") or parameter.__eq__("--looped-ips") or parameter.__eq__("--help") or parameter.__eq__("-h")):
        print_help()
else:
    print_help()
