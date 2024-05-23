import binascii
import sys
from pathlib import Path
from typing import List


class Probe:
    def __init__(self, name_in="", probe_in="", probe_hex_in="", rarity_in=-1, ports_in="", matchers_in=[]):
        self.name = name_in.replace("\n", "")
        self.probe = probe_in
        self.probe_hex = probe_hex_in.replace("\n", "")
        self.rarity = rarity_in
        self.ports = ports_in
        self.matchers = matchers_in

    def wrap(self, s, w):
        return [s[i:i + w] for i in range(0, len(s), w)]

    def get_full_port_range(self):
        ports_list = []
        for prts in self.ports.split(","):
            if not prts.__contains__("-"):
                ports_list.append(int(prts))
            else:
                for prt in range(int(prts.split("-")[0]), int(prts.split("-")[1])):
                    ports_list.append(prt)
        # return comma_separated_all_ports
        return ports_list

    def show_as_text(self):
        print("Name: " + self.name)
        print("NMAP-like probe: " + self.probe)
        print("ZMAP/UDPX-like probe: " + self.probe_hex)
        print("Rarity: " + str(self.rarity))
        print("Ports: " + self.ports)
        print("Matchers:\n")
        for m in self.matchers:
            print(m)

    def show_as_udpx(self):
        comma_separated_all_ports = ",".join(str(val) for val in self.get_full_port_range())
        # print(f"{{\n\tName: \"{self.name}\",\n\tPayloads: []string{{\"{self.probe_hex}\"}},\n\tPort: []int{{{comma_separated_all_ports}}},\n}},")
        return f"{{\n\tName: \"{self.name}\",\n\tPayloads: []string{{\"{self.probe_hex}\"}},\n\tPort: []int{{{comma_separated_all_ports}}},\n}},"

    def show_as_nmap_payloads(self):
        probe_split4nmap_payloads = ""
        for pr in self.wrap(self.probe_hex, 32):
            probe_split4nmap_payloads += "  \"\\x" + '\\x'.join(pr[i:i + 2] for i in range(0, len(pr), 2)) + "\"\n"
        comma_separated_all_ports = ",".join(str(val) for val in self.get_full_port_range())
        # print("#{}\nudp {}\n{}".format(self.name, comma_separated_all_ports, probe_split4nmap_payloads))
        return "#{}\nudp {}\n{}".format(self.name, comma_separated_all_ports, probe_split4nmap_payloads)


def nmap_probe2hex(probe: str):
    hex_probe = ""
    probe = probe.replace("\\0", "\\x00").replace("\\r", "\\x0d").replace("\\n", "\\x0a").replace("\\t", "\\x09")
    for i in probe.replace("\\x", "CHECK_VALUE3936462929474629302497\\x").split("CHECK_VALUE3936462929474629302497"):
        # print(i)
        if i.startswith("\\x") and len(i.replace("\\x", "")) == 2:
            hex_probe += i.replace("\\x", "")
        if i.startswith("\\x") and len(i.replace("\\x", "")) > 2:
            hex_probe += i.replace("\\x", "")[0] + i.replace("\\x", "")[1] + str(
                binascii.hexlify(bytes(i.replace("\\x", "")[2:len(i)], 'ascii')))
        if not i.startswith("\\x"):
            hex_probe += str(binascii.hexlify(bytes(i, 'ascii')))
    return hex_probe.replace("b'", "").replace("'", "")


def get_nmap_payloads_by_rarity(probes: List[Probe], rarity: int):
    result = ""
    for p in probes:
        if p.rarity == rarity:
            result += p.show_as_nmap_payloads() + "\n"
    out_file = open("./nmap-payloads_rarity_{}".format(rarity), "w")
    out_file.writelines(result)
    out_file.close()
    print("Generated nmap-payloads for rarity {}: ./nmap-payloads_rarity_{}".format(rarity, rarity))

"""
Get all UDP probes
"""
def get_structured_udp_probes(nsp: str):
    udp_probes_array = []
    with open(nsp, "r") as nsp_file:
        file = nsp_file.read()
        probes = file.split("Probe ")
        for p in probes:
            if p.startswith("UDP "):
                probe_name = p.split("UDP ", 1)[1].split(" q|")[0]
                probe_nmap_format = p.split("UDP ", 1)[1].split(" q|", 1)[1].split("|", 1)[0]
                probe_hex_format = nmap_probe2hex(p.split("UDP ", 1)[1].split(" q|", 1)[1].split("|", 1)[0])
                rarity = int(p.split(probe_nmap_format + "|")[1].split("rarity ")[1][0])
                ports = p.split(probe_nmap_format + "|")[1].split("ports ")[1].split('\n', 1)[0]
                matchers_string = p.split(probe_nmap_format + "|")[1].split("ports ")[1].split('\n', 1)[1]
                matchers = []
                for m in matchers_string.split("\n"):
                    if m.startswith("match ") or m.startswith("softmatch "):
                        matchers.append(m)
                udp_probes_array.append(Probe(probe_name, probe_nmap_format, probe_hex_format, rarity, ports, matchers))
    return udp_probes_array


def get_udpx_probes(udpx_probes_filename: str):
    udpx_probes_array = []
    with open(udpx_probes_filename) as udpx_probes_file:
        udpx_probes = udpx_probes_file.read().split("var Probes = []Probe{")[1].split("{\n\t\t")
        for udpx_probe in udpx_probes:
            if udpx_probe.__contains__("Name: "):
                probe_index = 0
                for probe_hex in udpx_probe.split(",\n\t\tPayloads: []string{")[1].split("},\n", 1)[0].split(", "):
                    probe_index += 1
                    udpx_probe_name = str(udpx_probe.split("Name: ")[1].split(",", 1)[0]).replace('"',
                                                                                                  '') + "_udpx_probe_{}".format(
                        probe_index)
                    udpx_probe_ports_range = udpx_probe.split("\t\tPort: []int{")[1].split("},\n", 1)[0]
                    udpx_probes_array.append(
                        Probe(udpx_probe_name, "", probe_hex.replace('"', ''), -1, udpx_probe_ports_range, []))
    return udpx_probes_array


def get_probe_by_name(name, probes: List[Probe]):
    for p in probes:
        if p.name == name:
            return p


def get_probe_by_hex_probe(hex_probe, probes: List[Probe]):
    for p in probes:
        if p.probe_hex.__eq__(hex_probe):
            return p
    return None


def get_commands_for_zmap(port_file, port_probe_file):
    with open(port_file, "r") as ports_file:
        ports = ports_file.readlines()
        with open(port_probe_file) as ports_probes_file:
            ports_probes = ports_probes_file.readlines()
            cmds = []
            for p in ports:
                for port_probe in ports_probes:
                    if p.replace("\n", "") == port_probe.split(",")[0].replace("\n", ""):
                        probe_name = port_probe.split(",")[1].replace("\n", "")
                        probe_hex = port_probe.split(",")[2].replace("\n", "")
                        port = p.replace("\n", "")
                        cmd = "sudo zmap -M udp -p {} --probe-args=hex:\"{}\" -w ./targets/TARGETS -T 4 -r 300000 -f saddr,sport,data -o ./results/{}-{}.result". \
                            format(
                            port,
                            probe_hex,
                            port,
                            probe_name)
                        # print(cmd)
                        cmds.append(cmd + '\n')
                        cmd_file = open("./zmap_commands2run.sh", "w")
                        cmd_file.writelines(cmds)
                        cmd_file.close()
    print("Generated file to scan with ZMAP: ./zmap_commands2run.sh")


def wrap(s, w):
    return [s[i:i + w] for i in range(0, len(s), w)]


def get_np_format_probe(hex_probe, probe_name, port):
    probe_split4nmap_payloads = ""
    for pr in wrap(hex_probe, 32):
        probe_split4nmap_payloads += "  \"\\x" + '\\x'.join(pr[i:i + 2] for i in range(0, len(pr), 2)) + "\"\n"
    return "#{}\nudp {}\n{}".format(probe_name, port, probe_split4nmap_payloads)


def get_commands_for_masscan(port_probe_file):
    # make dir for nmap-payloads separate files for masscan
    Path("./masscan_port_probes").mkdir(exist_ok=True)
    # create separate files for each port:probe and write a port:probe into this file in nmap-payloads format
    with open(port_probe_file) as ports_probes_file:
        ports_probes = ports_probes_file.readlines()
        cmds = []
        for port_probe in ports_probes:
            port_probe_port = port_probe.split(",")[0]
            port_probe_name = port_probe.split(",")[1]
            port_probe_hex = port_probe.split(",")[2]
            port_probe_file_contents = get_np_format_probe(port_probe_hex.replace("\n", ""),
                                                           port_probe_name.replace("\n", ""),
                                                           port_probe_port.replace("\n", ""))
            with open("masscan_port_probes/nmap_payloads_{}_{}".format(port_probe_port, port_probe_name),
                      "w") as port_probe_nmap_payloads_file:
                port_probe_nmap_payloads_file.write(port_probe_file_contents)
            cmd = "sudo masscan -i inet0 -p U:{} -iL ./targets/TARGETS --banners --output-filename {}-{}.result --rate 500000 --nmap-payloads ./masscan_port_probes/{}". \
                format(
                port_probe_port,
                port_probe_port,
                port_probe_name,
                "nmap_payloads_{}_{}".format(port_probe_port, port_probe_name))
            cmds.append(cmd + '\n')
            cmd_file = open("./masscan_commands2run.sh", "w")
            cmd_file.writelines(cmds)
            cmd_file.close()
    print("Generated file to scan with MASSCAN: ./masscan_commands2run.sh")


def generate_port_probes():
    """
    Form port:probe pairs
    """
    ports_source_file = "ports"  # handcrafted list during research
    with open(ports_source_file) as ports_file:  # our ports
        ports = ports_file.readlines()
    udp_probes = get_structured_udp_probes("nmap-service-probes")
    port_probes_array = {}
    # init port_probe array
    for port in ports:
        port_probes_array[port.replace("\n", '')] = []

    # """
    # Enrich with CyberOK hand-crafted port:probe file
    # this will break your original port list and supply it with extra ports to scan for
    # """
    # with open("port_probe", "r") as handcrafted_port_probe:
    #     hand_port_probes = handcrafted_port_probe.readlines()
    #     for pp in hand_port_probes:
    #         if str(int(pp.split(",")[0])) in port_probes_array:
    #             # port_probes_array[pp.split(",")[0]].append(pp.split(",")[1].replace("\n", ""))
    #             port_probes_array[pp.split(",")[0]].append(
    #                 get_probe_by_name(pp.split(",")[1].replace("\n", ""), udp_probes))
    #         else:
    #             port_probes_array[pp.split(",")[0]] = []
    #             # port_probes_array[pp.split(",")[0]].append(pp.split(",")[1].replace("\n", ""))
    #             port_probes_array[pp.split(",")[0]].append(
    #                 get_probe_by_name(pp.split(",")[1].replace("\n", ""), udp_probes))

    """
    Get port:probe connections by port number from nmap-service-probes
    """
    for port in ports:
        for probe in udp_probes:
            if int(port) in probe.get_full_port_range():
                port_probes_array[str(int(port))].append(probe)
    # print(port_probes_array)

    """
    udpx enrich
    """
    udpx_probes_array = get_udpx_probes("probes.go")
    # rename udpx extracted probe, if its hex probe is equal to one in nmap-service-probes
    for udpx_p in udpx_probes_array:
        for p in udp_probes:
            if udpx_p.probe_hex.lower() == p.probe_hex.lower():
                udpx_p.name = p.name
    for port in ports:
        for udpx_p in udpx_probes_array:
            if int(port) in udpx_p.get_full_port_range() and port.replace("\n", "") in port_probes_array:
                port_probes_array[port.replace("\n", "")].append(udpx_p)

    """
    nmap-payloads enrich
    the real file sometimes has no normal parsable name, so use the one from this repo  
    """
    nmap_payloads_probes = []
    with open("nmap-payloads", "r") as nmap_payloads_file:
        nmap_payloads = nmap_payloads_file.read()
        for p in nmap_payloads.split("#"):
            if len(p) > 0:
                nmp_probe_name = p.split("\n", 1)[0].replace(" ", "") + "_nmap_payloads"
                nmp_ports = p.split("\n", 1)[1].split("udp ")[1].split("\n")[0]
                nmp_probe = ""
                for i in p.split("\n", 1)[1].split("udp ")[1].split("\n"):
                    if i.__contains__('"'):
                        nmp_probe += i.replace('"', '')
                nmap_payloads_probes.append(
                    Probe(nmp_probe_name, nmp_probe, nmap_probe2hex(nmp_probe.replace("  ", "")), -1, nmp_ports, []))

    for port in ports:
        for nmp_p in nmap_payloads_probes:
            if int(port) in nmp_p.get_full_port_range() and port.replace("\n", "") in port_probes_array:
                port_probes_array[port.replace("\n", "")].append(nmp_p)

    """
    Form final list for output
    """
    # print(port_probes_array)
    final_list_port_probes = []
    for pp in port_probes_array:
        if len(port_probes_array[pp]) > 0:
            for p in port_probes_array[pp]:
                final_list_port_probes.append(str(pp + "," + p.name + "," + str(p.probe_hex).lower()).replace(" ", ""))
        else:
            final_list_port_probes.append(str(pp + ","))

    """
    Remove duplicate port,probe pairs under different names
    """
    final_list_port_probes = list(set(final_list_port_probes))
    final_list_port_probes.sort()
    for pp in final_list_port_probes:
        if len(pp.split(",")) == 3:
            curr_port = pp.split(",")[0]
            curr_hex_probe = pp.split(",")[2]
            for sub_p in final_list_port_probes:
                if not final_list_port_probes.index(sub_p) == final_list_port_probes.index(pp):
                    if len(sub_p.split(",")) == 3:
                        curr_sub_port = sub_p.split(",")[0]
                        curr_sub_hex_probe = sub_p.split(",")[2]
                        if curr_sub_hex_probe == curr_hex_probe and curr_sub_port == curr_port:
                            final_list_port_probes.pop(final_list_port_probes.index(sub_p))
        # if no probe found for port, use NullProbe
        if len(pp.split(",")) < 3:
            final_list_port_probes[final_list_port_probes.index(pp)] = pp + "NullUdpProbe,00"

    """
    Add NullProbe to every port, that has no probe suggested
    """
    # write final port:probe list to file
    final_list_port_probes = list(set(final_list_port_probes))
    final_list_port_probes.sort()
    with open("./port_probe_generated_by_{}_file".format(ports_source_file), "w") as port_probe_new_file:
        port_probe_new_file.write('\n'.join(final_list_port_probes))
    return port_probes_array


def generate_nmap_payloads():
    pps = generate_port_probes()
    probes = ""
    for pp in pps:
        for p in pps[pp]:
            probes += p.show_as_nmap_payloads() + "\n"
        with open("./nmap-payloads_generated", "w") as np_file:
            np_file.write(probes)
    print("Generated file: ./nmap-payloads_generated")


def generate_udpx():
    pps = generate_port_probes()
    probes = ""
    for pp in pps:
        for p in pps[pp]:
            probes += p.show_as_udpx() + "\n"
        with open("./udpx_generated", "w") as udpx_file:
            udpx_file.write(probes)
    print("Generated file: ./udpx_generated")


def print_help():
    print("Help:")
    print("\tpython3 udp_scan.py [PARAM] [OPTIONS]")
    print("")
    print("To generate script to scan with ZMAP:")
    print("\tpython3 udp_scan.py --generate-scan zmap")
    print("")
    print("To generate script to scan with MASSCAN:")
    print("\tpython3 udp_scan.py --generate-scan masscan")
    print("")
    print("To generate file with probes in UDPX format:")
    print("\tpython3 udp_scan.py --get-probes udpx")
    print("")
    print("To generate file with probes in NMAP-PAYLOADS format:")
    print("\tpython3 udp_scan.py --get-probes nmap-payloads")
    print("")
    print("To generate file with probes in NMAP-PAYLOADS format with exact RARITY:")
    print("\tpython3 udp_scan.py --get-probes nmap-payloads 1")


if len(sys.argv) > 2:
    parameter = sys.argv[1]
    mode = sys.argv[2]

    probes = generate_port_probes() # dict structure port:probes
    all_probes = [] # list of probes
    for prb in probes:
        for p in probes[prb]:
            all_probes.append(p)

    all_probes = list(set(all_probes))
    if parameter.__eq__("--help") or parameter.__eq__("-h"):
        print_help()

    if parameter.__eq__("--generate-scan") and len(sys.argv) > 2:
        if mode.__eq__("masscan"):
            print("Generating commands for masscan...")
            get_commands_for_masscan("port_probe_generated_by_ports_file")
        elif mode.__eq__("zmap"):
            print("Generating commands for zmap...")
            get_commands_for_zmap("ports", "port_probe_generated_by_ports_file")
        else:
            print_help()

    if parameter.__eq__("--get-probes") and len(sys.argv) > 2:
        if mode.__eq__("udpx"):
            print("Generating udpx file:")
            generate_udpx()
        if mode.__eq__("nmap-payloads") and not len(sys.argv) == 4:
            print("Generating nmap-payloads file:")
            generate_nmap_payloads()
        if mode.__eq__("nmap-payloads") and len(sys.argv) == 4:
            print("Generating nmap-payloads original file for rarity {}:".format(sys.argv[3]))
            get_nmap_payloads_by_rarity(all_probes, int(sys.argv[3]))

    if not (parameter.__eq__("--generate-scan") or parameter.__eq__("--get-probes") or parameter.__eq__("--help") or parameter.__eq__("-h")):
        print_help()
else:
    print_help()
