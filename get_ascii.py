import sys

def get_ascii_only(string_banner):
    string_banner = string_banner.encode('ascii')
    print(string_banner.decode('ascii'))
    banner = bytes.fromhex(string_banner.decode('ascii'))
    new_banner = ""
    # for i in banner.decode('utf-8', "replace"):
    for i in banner.decode('ascii', "ignore"):
        if ord(i) in range(32, 126):
            new_banner += chr(ord(i)).replace('\\', '\\\\')
        else:
            new_banner += " "
    new_banner = ' '.join(new_banner.split())
    return new_banner.replace('\n', '')

file = sys.argv[1]
with open(file, "r") as file_to_analyze:
    lines = file_to_analyze.readlines()
    for l in lines:
        if not l.__contains__("data") and len(l.split(",")[2]) > 1:
            print(l.split(",")[0] +":" + get_ascii_only(l.split(",")[2]))

# script works with the following zmap output format: saddr,sport,data
