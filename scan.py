import sys
import json
import time
import subprocess
import re
import requests
import socket
import maxminddb

def ipv(domain, record_type):
    resolvers = [
        "208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", "94.140.14.14", 
        "185.228.168.9", "76.76.2.0", "76.76.19.19", "129.105.49.1", "74.82.42.42", 
        "205.171.3.65", "193.110.81.0", "147.93.130.20", "51.158.108.203"
    ]
    addresses = set()
    
    for resolver in resolvers:
        try:
            result = subprocess.check_output(["nslookup", "-type=" + record_type, domain, resolver], 
                                             timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            
            for line in result.split("\n"):
                match = re.search(r'Address:\s+([\d\w:.]+)', line)
                if match:
                    ip = match.group(1)
                    if ip not in resolvers:
                        addresses.add(ip)
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError:
            continue
    return list(addresses)


def http_server(link):
    try:
        r = requests.get("https://" + link)
        # print(r)
        result = None
        result = r.headers.get("Server")
        return result
    except requests.exceptions.RequestException:
        print("Error", file=sys.stderr)

def http(link, redirect_count=0, port=80):
    if redirect_count > 10:
        return -1, hsts
    
    try:
        sock = socket.create_connection((link, port), timeout=3)
    except (socket.timeout, socket.error):
        return -1, hsts

    request = f"GET / HTTP/1.0\r\nHost: {link}\r\n\r\n"
    sock.sendall(request.encode())

    response = b""
    while True:
        chunk = sock.recv(4096)
        if len(chunk) == 0:
            break
        response += chunk

    sock.close()

    split_response = response.split(b"\r\n\r\n", 1)
    headers = split_response[0].decode(errors="ignore").split("\r\n")
    
    # print(headers)

    try:
        status_code = int(headers[0].split(" ")[1])
    except (IndexError, ValueError):
        return -1  
    
    location = None
    hsts = False
    for line in headers:
        if line.lower().startswith("location:"):
            location = line.split(": ", 1)[1]
        if line.lower().startswith("strict-transport-security:"):
            hsts = True

    # print(status_code)
    # print(location)

    if status_code == 200:
        return redirect_count, hsts
    elif 300 <= status_code < 400 and location:
        if location.lower().startswith("https"):
            return "redirect", hsts
        if location.startswith("http"):
            new_host = location.split("/")[2]
        else:
            new_host = link
        return http(new_host, redirect_count + 1, port=443)
    else:
        return -1, hsts
    
def tls_1_3(line):
    try:
        result = subprocess.check_output(["openssl", "s_client", "-tls1_3", "-connect", "tls13." + line + ":443"], input=b'',
            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        if result:
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        return False
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        return False

def tls_versions(line):
    versions = []
    result = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", line],
            stderr=subprocess.STDOUT).decode("utf-8")
    if "TLSv1.2" in result:
        versions.append("TLSv1.2")
    if "TLSv1.1" in result:
        versions.append("TLSv1.1")
    if "TLSv1.0" in result:
        versions.append("TLSv1.0")
    if "SSLv2" in result:
        versions.append("SSLv2")
    if "SSLv3" in result:
        versions.append("SSLv3")
    if tls_1_3(line):
        versions.append("TLSv1.3")
    # print(result)
    return versions

def root_ca(line):
    try:
        result = subprocess.check_output(["openssl", "s_client", "-connect", line + ":443"], input=b'',  # Simulate the echo
            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

        result_lines = result.splitlines()

        for i in result_lines:
            match = re.search(r" O = ([^\n]+)", i)
            if match:
                print(match.group(1).strip().split(",")[0])
                return match.group(1).strip().split(",")[0]
        return None

    except subprocess.TimeoutExpired:
        return None
    except subprocess.CalledProcessError as e:
        return None
    except FileNotFoundError:
        return None

def rdns_names(ipv4_list):
    results= []
    try: 
        for addr in ipv4_list:
            result = subprocess.check_output(["nslookup", addr],
                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            result_lines = result.splitlines()
            for i in result_lines:
                match = re.search(r"name\s*=\s*(.+)", i)
                if match:
                    # print(match)
                    results.append(match.group(1).strip())
        # print(results)
        return results
    except subprocess.TimeoutExpired:
        return results
    except subprocess.CalledProcessError as e:
        return results
    except FileNotFoundError:
        return results

def get_rtt(ipv4_list, port):
    results = []
    try: 
        for addr in ipv4_list:
                cmd = f'time (echo -e "\x1dclose\x0d" | telnet {addr} {port})'
                result = subprocess.check_output(['sh', '-c', cmd],
                    timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                match = re.search(r"real\s+(\d+)m([\d.]+)s", result)
                if match:
                    minutes = int(match.group(1))
                    seconds = float(match.group(2))
                    rtt = (minutes * 60 + seconds) * 1000
                    results.append(rtt)
        return results if results else None
    except subprocess.TimeoutExpired:
        return None
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        return None
    
# https://stackoverflow.com/questions/952914/how-do-i-make-a-flat-list-out-of-a-list-of-lists
def flatten(xss):
    return [x for xs in xss for x in xs]

def rtt_range(ipv4_list):
    results = []
    ports = [80, 22, 443]
    for port in ports:
        res = get_rtt(ipv4_list, port)
        if res is not None:
            results.append(get_rtt(ipv4_list, port))
    flat_results = flatten(results)
    return [int(min(flat_results)), int(max(flat_results))] if results else None
    
    
def geo_locations(ipv4_list):
    locations = set()
    try:
        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            for addr in ipv4_list:
                data = reader.get(addr)
                if data:
                    city = data.get("city", {}).get("names", {}).get("en", "")
                    subdivision = data.get("subdivisions", [{}])[0].get("names", {}).get("en", "")
                    country = data.get("country", {}).get("names", {}).get("en", "")
                    
                    if city and subdivision and country:
                        location = city + ", " + subdivision + ", " + country
                    else:
                        continue
                    locations.add(location)
        return list(locations)
    except FileNotFoundError:
        return []
    except Exception as e:
        return []

def write_output(input, output):
    results = {}
    file = open(input, "r")
    output_file = open(output, "w")
    for line in file:
        ipv4 = ipv(line.strip(), "A")
        insecure_http = False
        redirect = False
        hsts = False
        temp = http(line.strip(), 0)
        if temp[0] == 0:
            insecure_http = True
        elif temp[0] == "redirect":
            redirect = True
        if temp[1] == True:
            hsts = True
        results[line.strip()] = {"scan_time" : time.time(), "ipv4_addresses" : ipv4, "ipv6_addresses": ipv(line.strip(), "AAAA"), 
                               "http_server": http_server(line.strip()), "insecure_http": insecure_http, "redirect_to_https": redirect,
                               "hsts": hsts, "tls_versions": tls_versions(line.strip()), "root_ca": root_ca(line.strip()),
                               "rdns_names" : rdns_names(ipv4), "rtt_range": rtt_range(ipv4), "geo_locations" : geo_locations(ipv4)}
    json.dump(results, output_file, sort_keys=True, indent=4)
    # print(input, output)
    output_file.close()

if __name__ == "__main__":
    input = sys.argv[1]
    output = sys.argv[2]
    write_output(input, output)