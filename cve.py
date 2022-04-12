import requests
import json

# This function is used for fetching the CVEs from NVD database
def get_results(vendor, product, version):
    soup_url = "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeName=cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*".format(
        vendor, product, version)
    r = requests.get(soup_url)
    # print(r)
    d = r.json()
    noofresults = d['totalResults']
    print("\n[+] No Of CVEs " + str(noofresults))
    # TODO Check this URL
    print('[+] Retrieving CVEs From The NVD Database')
    soup_url = "https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage={}&cpeName=cpe:2.3:*:{}:{}:{}" \
               ":*:*:*:*:*:*:*".format(noofresults, vendor, product, version)
    r = requests.get(soup_url)
    d = r.json()
    print('[+] Finished Retrieving\n\n')
    return d


# This function is used for fetching the description of CVEs from NVD database
def getDesc(cve, vendor, soup):
    url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
    try:
        response = requests.get(url + cve)
    except Exception:
        print("[-] No Internet Connectivity")
    data = response.content.decode('utf-8')
    try:
        cve = json.loads(data)
        cve_item = cve['result']['CVE_Items'][0]
        desc = cve_item['cve']['description']['description_data'][0]['value']
        configuration = cve_item['configurations']
        match_voa(configuration, vendor, soup)
        return desc
    except Exception:
        desc = "Exception"
        return desc


def find_voa(cpe23uri):
    if '\\' in cpe23uri:
        cpe23uri = cpe23uri.replace('\\', '')
    cpe23uri = cpe23uri.split(':')
    output = [cpe23uri[2]]
    output.append(cpe23uri[3])
    output.append(cpe23uri[4])
    return output


# This function is used for determining if CVEs is Running On
def match_voa(configurations, vendor, soup):
    os = soup
    temp = [''] * 2
    nodes = configurations['nodes']

    node_q = []
    for node in nodes:
        if node['operator'] == "OR":
            node_q.append(node)
        else:
            if node['children']:
                node_q.extend(node['children'])
            else:
                node_q.append(node)

    cpe_match_list = []
    for node in node_q:
        cpe_match_list.extend(node['cpe_match'])

    for cpe_match in cpe_match_list:
        out = find_voa(cpe_match['cpe23Uri'])
        if out[0] == 'a' and temp[0] == '':
            temp[0] = out[1]
            temp[1] = out[2]
        if out[1] == vendor and out[2] == os:
            if cpe_match['vulnerable']:
                return [out[1], out[2], '']

    return [temp[0], '', temp[1]]


# This function is used to fetch basic CVE details from the allcve
def cve_details(cve, vendor, soup):
    details = []
    cve_id = cve['cve']["CVE_data_meta"]["ID"]
    details.append(cve_id)
    desc = cve['cve']["description"]["description_data"][0]["value"]
    details.append(desc)
    voa = match_voa(cve['configurations'], vendor, soup)
    details.append(voa)
    return details
