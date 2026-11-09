from checkdmarc.spf import query_spf_record, parse_spf_record
import json

def spf_tree(domain, nameservers=None, timeout=3.0):
    q = query_spf_record(domain, nameservers=nameservers, timeout=timeout)
    #print(q)
    res = parse_spf_record(q["record"], domain, nameservers=nameservers, timeout=timeout)
    print(json.dumps(res, indent=4))
    return res  # contient 'parsed', 'dns_lookups', 'warnings'


if __name__ == "__main__":
    domain = "chorum-direct.fr"
    # tu peux fixer tes DNS ici (ex. 8.8.8.8 si tu veux)
    nameservers = ["8.8.8.8", "1.1.1.1"]
    res = spf_tree(domain, nameservers=nameservers)
    print("DNS lookups:", res.get("dns_lookups"))
    print("Warnings:", res.get("warnings"))
    #print("Flattened:", flat)
