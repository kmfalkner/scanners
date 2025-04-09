import json
import time
from collections import Counter
from texttable import Texttable

def generate_report(data):
    report = []
    
    report.append("Information from part 2:")

    for key, value in data.items():
        report.append(f"domain: {key}")
        report.append(json.dumps(value, indent=4))
        report.append("\n")
    
    rtt_data = []
    for key, value in data.items():
        rtt_range = value.get("rtt_range")
        if not isinstance(rtt_range, list):
            rtt_range = [None, None]
        min_rtt, max_rtt = rtt_range
        min_rtt = min_rtt if min_rtt is not None else "null"
        max_rtt = max_rtt if max_rtt is not None else "null"
        rtt_data.append((key, min_rtt, max_rtt))
    rtt_data.sort(key=lambda x: (x[1] if not isinstance(x[1], str) else float('inf')))
    rtt_table = Texttable()
    rtt_table.header(["domain", "minimum RTT", "maximum RTT"])
    rtt_table.add_rows(rtt_data, header=False)
    report.append("RTT Ranges:")
    report.append(rtt_table.draw())

    counts = {}
    # for v in data.values():
    #     print("HEREHERHEHRERHERHER\n", v.get("root_ca"))
    for val in data.values():
        temp = val.get("root_ca")
        if temp in counts:
            counts[temp] += 1
        else:
            counts[temp] = 1
    sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    table = Texttable()
    table.header(["certificate authority", "number of occurances"])
    table.add_rows(sorted_counts, header=False)
    report.append("\nRoot CA Occurrences:\n" + table.draw())
    
    ws_counts = {}
    for val in data.values():
        temp = val.get("http_server", "null")
        if temp in ws_counts:
            ws_counts[temp] += 1
        else:
            ws_counts[temp] = 1
    ws_sorted_counts = sorted(ws_counts.items(), key=lambda x: x[1], reverse=True)
    ws_table = Texttable()
    ws_table.header(["web server name", "number of occurances"])
    ws_table.add_rows(ws_sorted_counts, header=False)
    report.append("\nWeb Server Occurrences:\n" + ws_table.draw())
    
    sd_counts = {"SSLv2" : 0, "SSLv3" : 0, "TLSv1.0" : 0, "TLSv1.1" : 0, "TLSv1.2" : 0, "TLSv1.3" : 0}
    for val in data.values():
        tls_versions = val.get("tls_versions", [])
        for tls in tls_versions:
            sd_counts[tls] +=1 
    total_domains = len(data)
    feature_table = Texttable()
    feature_table.header(["scanned domain", "percentage"])
    feature_table.add_rows([(tls, (count / total_domains) * 100) for tls, count in sorted(sd_counts.items(), key=lambda x: x[1], reverse=True)], header=False)
    
    f_counts = {"insecure_http" : 0, "redirect_to_https": 0, "hsts":0, "ipv6_addresses": 0}
    for val in data.values():
        if val.get("insecure_http"):
            f_counts["insecure_http"] += 1
        if val.get("redirect_to_https"):
            f_counts["redirect_to_https"] += 1
        if val.get("hsts"):
            f_counts["hsts"] += 1
        if val.get("ipv6_addresses"):
            f_counts["ipv6_addresses"] += 1
    # f_sorted_counts = sorted(f_counts.items(), key=lambda x: x[1], reverse=True)
    feature_table.add_rows([(feature, (count / total_domains) * 100) for feature, count in f_counts.items()], header=False)
    report.append("\nPercentage of each Scanned Domain:\n" + feature_table.draw())
    
    return "\n".join(report)

def main(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)
    report = generate_report(data)
    with open(output_file, 'w') as f:
        f.write(report)

if __name__ == "__main__":
    import sys
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    main(input_file, output_file)
