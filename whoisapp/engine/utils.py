from .models import TopLevelDomain,WhoisServer
import json
import dateutil.parser
from django.db.models.functions import Length
import xmltodict
import socket

TLD_FIELDS_MAP =  {
    '@name':"name",
    'countryCode' : "country_code" ,
    "created": 'created',
    "changed": 'changed',
    "registrationService":"registar",
    "source": "source",
    "state": "state",
    "domain": "domain"
}


WHOIS_FIELDS_MAP = {
    "@host" : "host",
    "source" : "source",
    "queryFormat" : "queryFormat",
    "availablePattern" : "errorPattern",
    "errorPattern" : "errorPattern"
}


def get_data_from_xml():
    fpath = "engine/data/whois-server-list.xml"
    f = open(fpath, 'r')
    data = f.read()
    f.close()
    parsed = xmltodict.parse(data)
    dict_data = json.loads(json.dumps(parsed)) # OrderedDict -> Dict conversion
    return dict_data


def ws_get_or_create(ws_dict):
    host = ws_dict.get('@host')
    if host.endswith('.'):
        host =  host[:-1]
    try:
        return WhoisServer.objects.get(host=host)
    except WhoisServer.DoesNotExist:
        pass
    ws_item = {}
    for k in ws_dict.keys():
        ws_item[WHOIS_FIELDS_MAP[k]] = ws_dict[k]
    ws = WhoisServer(**ws_item)
    ws.save()
    return ws


def prepare_tld_entry(entry):
    tld_dict = {}
    for k in entry.keys():
        if k in  ["whoisServer", "domain"]:
            continue
        if k in ['changed',"created"]:
            tld_dict[k] = dateutil.parser.parse(str(entry[k]))
            continue
        tld_dict[TLD_FIELDS_MAP[k]] = entry[k]
    return tld_dict


def tld_get_or_create(entry,parent=None):
    name = entry.get('@name')
    try:
        tld = TopLevelDomain.objects.get(name=name)
    except TopLevelDomain.DoesNotExist:
        tld_dict = prepare_tld_entry(entry)
        tld = TopLevelDomain(**tld_dict)
        if parent:  tld.parent = parent
        tld.save()
    return tld


def handle_entry(entry, parent=None):
    name = entry.get('@name')
    print "[handle_entry]", "-----------"*bool(parent), name, parent
    domains = entry.get('domain', [])
    whois_servers = entry.get('whoisServer')
    tld = tld_get_or_create(entry, parent)

    if whois_servers:
        if isinstance(whois_servers, dict):  whois_servers = [whois_servers]
        for ws in whois_servers:
            ws_item = ws_get_or_create(ws)
            if ws_item not in tld.whois.all():
                tld.whois.add(ws_item)
    if domains:
        if isinstance(domains, dict):   domains = [domains]
        for domain in domains:
            handle_entry(domain, parent=tld)


def parse_data():
    data = get_data_from_xml()
    records =  data.get('domainList').get('domain')
    for entry in records:
        handle_entry(entry)

    print "[parse_data] Finished"


def get_names():
    data = get_data_from_xml()
    records = data.get('domainList').get('domain')
    names = []
    for entry in records:
        names.append(entry.get('@name'))
        domains = entry.get('domain')
        if domains:
            if isinstance(domains, dict):
                 names.append(domains.get('@name'))
            elif isinstance(domains, list):
                for d in domains:
                    names.append(d.get('@name'))
            else:
                print "Unrecognized domain data", domains
    return names


def get_ws():
    data = get_data_from_xml()
    records = data.get('domainList').get('domain')
    ws = []
    for entry in records:
        whois_servers = entry.get('whoisServer')
        if whois_servers:
            if not isinstance(whois_servers, list):
                whois_servers = [whois_servers]
            for k in whois_servers:
                ws.append(k.get('@host'))

        domains = entry.get('domain')
        if domains:
            if isinstance(domains, dict):
                 domains = [domains]
            for d in domains:
                whois_servers = d.get('whoisServer')
                if whois_servers:
                    if not isinstance(whois_servers, list):
                        whois_servers = [whois_servers]
                    for p in whois_servers:
                        ws.append(p.get('@host'))
    return ws


def get_whois_for_domain(domain):
    splitted = domain.split('.')
    variants = ['.'.join(splitted[i:]) for i in range(len(splitted))] # a.b.c.d.e -> ['a.b.c.d.e','b.c.d.e','c.d.e','d.e','e']
    q = TopLevelDomain.objects.filter(name__in=variants).order_by(Length('name').asc())
    assert q.count(), "Not valid domain name"
    sub = q.last() # the longest subdomain
    if sub.whois.count():
        return sub.whois.first()
    elif sub.parent:
        return sub.parent.whois.first()
    return None




def perform_whois_query(domain):
    ws =  get_whois_for_domain(domain)
    query = domain
    if ws.queryFormat:
        query = ws.queryFormat % domain
    server  = ws.host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 43))
    s.send(query + "\r\n")
    response = ""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    return response


