# -*- encoding: utf-8 -*-
import time
import os
import random
import json
import math
import sys
from collections import OrderedDict, Counter, defaultdict
from samba.emulate import traffic_packets
from samba.samdb import SamDB
import ldb
from samba.dcerpc import ClientConnection
from samba.dcerpc import security, drsuapi, misc, nbt, lsa, drsblobs
from samba.drs_utils import drs_DsBind


SLEEP_OVERHEAD = 3e-4

# we don't use None, because it complicates [de]serialisation
NON_PACKET = '-'

CLIENT_CLUES = {
    ('dns', '0'): 1.0,      # query
    ('smb', '0x72'): 1.0,   # Negotiate protocol
    ('ldap', '0'): 1.0,     # bind
    ('ldap', '3'): 1.0,     # searchRequest
    ('ldap', '2'): 1.0,     # unbindRequest
    ('cldap', '3'): 1.0,
    ('dcerpc', '11'): 1.0,  # bind
    ('dcerpc', '14'): 1.0,  # Alter_context
    ('nbns', '0'): 1.0,     # query
}

SERVER_CLUES = {
    ('dns', '1'): 1.0,      # response
    ('ldap', '1'): 1.0,     # bind response
    ('ldap', '4'): 1.0,     # search result
    ('ldap', '5'): 1.0,     # search done
    ('cldap', '5'): 1.0,
    ('dcerpc', '12'): 1.0,  # bind_ack
    ('dcerpc', '13'): 1.0,  # bind_nak
    ('dcerpc', '15'): 1.0,  # Alter_context response
}

WAIT_SCALE = 20.0
WAIT_THRESHOLD = (1.0 / WAIT_SCALE)
NO_WAIT_LOG_TIME_RANGE = (-10, -3)


def random_colour_print():
    n = 18 + random.randrange(214)
    prefix = "\033[38;5;%dm" % n

    def p(*args):
        for a in args:
            print "%s%s\033[00m" % (prefix, a)

    return p


class FakePacketError(Exception):
    pass


class Packet(object):
    def __init__(self, fields):
        if isinstance(fields, str):
            fields = fields.rstrip('\n').split('\t')

        (timestamp,
         ip_protocol,
         stream_number,
         src,
         dest,
         protocol,
         opcode,
         desc) = fields[:8]
        extra = fields[8:]

        self.timestamp = float(timestamp)
        self.ip_protocol = ip_protocol
        try:
            self.stream_number = int(stream_number)
        except (ValueError, TypeError):
            self.stream_number = None
        self.src = int(src)
        self.dest = int(dest)
        self.protocol = protocol
        self.opcode = opcode
        self.desc = desc
        self.extra = extra

        if self.src < self.dest:
            self.endpoints = (self.src, self.dest)
        else:
            self.endpoints = (self.dest, self.src)

    def as_summary(self, time_offset=0.0):
        extra = '\t'.join(self.extra)
        t = self.timestamp + time_offset
        return (t, '%f\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s' %
                (t,
                 self.ip_protocol,
                 self.stream_number or '',
                 self.src,
                 self.dest,
                 self.protocol,
                 self.opcode,
                 self.desc,
                 extra))

    def __str__(self):
        return ("%.3f: %d -> %d; ip %s; strm %s; prot %s; op %s; desc %s %s" %
                (self.timestamp, self.src, self.dest, self.ip_protocol or '-',
                 self.stream_number, self.protocol, self.opcode, self.desc,
                 ('«' + ' '.join(self.extra) + '»' if self.extra else '')))

    def __repr__(self):
        return "<Packet @%s>" % self

    def copy(self):
        return self.__class__([self.timestamp,
                               self.ip_protocol,
                               self.stream_number,
                               self.src,
                               self.dest,
                               self.protocol,
                               self.opcode,
                               self.desc] + self.extra)

    def as_packet_type(self):
        t = '%s:%s' % (self.protocol, self.opcode)
        return t

    def client_score(self):
        """A positive number means we think it is a client; a negative number
        means we think it is a server. Zero means no idea. range: -1 to 1.
        """
        key = (self.protocol, self.opcode)
        if key in CLIENT_CLUES:
            return CLIENT_CLUES[key]
        if key in SERVER_CLUES:
            return -SERVER_CLUES[key]
        return 0.0


    def play(self, conversation, context):
        fn_name = 'packet_%s_%s' % (self.protocol, self.opcode)
        try:
            fn = getattr(traffic_packets, fn_name)

        except AttributeError as e:
            print >>sys.stderr, "Missing handler %s" % fn_name
            return

        print >>sys.stderr, "Calling handler %s" % fn_name

        fn(self, conversation, context)

    def __cmp__(self, other):
        return self.timestamp - other.timestamp




class ReplayContext(object):
    def __init__(self, server, lp, creds):
        self.server = server
        self.ldap_connections = []
        self.dcerpc_connections = []
        self.lsarpc_connections = []
        self.drsuapi_connections = []
        self.creds = creds
        self.lp = lp

        self.generate_ldap_search_tables()


    def generate_ldap_search_tables(self):
        self.samdb = SamDB('ldap://%s' % self.server,
                           lp=self.lp,
                           credentials=self.creds)
        self.base_dn = self.samdb.domain_dn()

        res = self.samdb.search(self.base_dn,
                         scope=ldb.SCOPE_SUBTREE,
                         attrs=['dn'])

        # find a list of dns for each pattern
        # e.g. CN,CN,CN,DC,DC
        self.dn_map = {}
        self.attribute_clue_map = {
            'invocationId': []
        }

        for r in res:
            dn = str(r.dn)
            pattern = ','.join(x.lstrip()[:2] for x in dn.split(',')).upper()
            dns = self.dn_map.setdefault(pattern, [])
            dns.append(dn)
            if dn.startswith('CN=NTDS Settings,'):
                self.attribute_clue_map['invocationId'].append(dn)

        # extend the map in case we are working with a different
        # number of DC components.
        #for k, v in self.dn_map.items():
        #    print >>sys.stderr, k, len(v)

        for k, v in self.dn_map.items():
            if k[-3:] != ',DC':
                continue
            p = k[:-3]
            while p[-3:] == ',DC':
                p = p[:-3]
            for i in range(5):
                p += ',DC'
                if p != k and p in self.dn_map:
                    print >> sys.stderr, 'dn_map collison %s %s' % (k, p)
                    continue
                self.dn_map[p] = self.dn_map[k]

        #print >>sys.stderr, 'post remap'
        #for k, v in self.dn_map.iteritems():
        #    print >>sys.stderr, k, len(v)

    def get_matching_dn(self, pattern, attributes=None):
        # If the pattern is an empty string, we assume ROOTDSE,
        # Otherwise we try adding or removing DC suffixes, then
        # shorter leading patterns until we hit one.
        # e.g if there is no CN,CN,CN,CN,DC,DC
        # we first try       CN,CN,CN,CN,DC
        # and                CN,CN,CN,CN,DC,DC,DC
        # then change to        CN,CN,CN,DC,DC
        # and as last resort we use the base_dn
        attr_clue = self.attribute_clue_map.get(attributes)
        if attr_clue:
            return random.choice(attr_clue)

        pattern = pattern.upper()
        while pattern:
            if pattern in self.dn_map:
                return random.choice(self.dn_map[pattern])
            # chop one off the front and try it all again.
            pattern = pattern[3:]

        return self.base_dn


    def get_dcerpc_connection(self, new=False):
        guid = '12345678-1234-abcd-ef00-01234567cffb' # RPC_NETLOGON UUID
        #'e1af8308-5d1f-11c9-91a4-08002b14a0fa' #EPMv4 UUID
        if self.dcerpc_connections and not new:
            return self.dcerpc_connections[-1]
        c = ClientConnection("ncalrpc:%s" % self.server,
                             guid, self.lp)
        self.dcerpc_connection.append(c)
        return c

    def get_lsarpc_connection(self, new=False):
        binding_options = '' # could be 'sign'

        if self.lsarpc_connections and not new:
            return self.lsarpc_connections[-1]

        c = lsa.lsarpc("ncacn_ip_tcp:%s[%s]" % (self.server, binding_options),
                       self.lp, self.creds)

        self.lsarpc_connection.append(c)
        return c

    def get_drsuapi_connection_pair(self, new=False, unbind=False):
        """get a (drs, drs_handle) tuple"""
        if self.drsuapi_connections and not new:
            c = self.drsuapi_connections[-1]
            if unbind:
                del self.drsuapi_connections[-1]
            return c

        binding_options = '' # could be 'seal'
        binding_string = "ncacn_ip_tcp:%s[%s]" % (self.server, binding_options)
        drs = drsuapi.drsuapi(binding_string, self.lp, self.creds)
        (drs_handle, supported_extensions) = drs_DsBind(drs)

        ###XX orther places do:
        # bind_info = drsuapi.DsBindInfoCtr()
        # bind_info.length = 28
        # bind_info.info = drsuapi.DsBindInfo28()
        # bind_info.info.supported_extensions	= 0
        # (info, handle) = drs.DsBind(misc.GUID(drsuapi.DRSUAPI_DS_BIND_GUID), bind_info)

        c = (drs, drs_handle)

        if not unbind:
            self.drsuapi_connection.append(c)

        return c

    def get_ldap_connection(self, new=False):
        if self.ldap_connections and not new:
            return ldap_connections[-1]

        samdb = SamDB('ldap://%s' % self.server,
                      credentials=self.creds, lp=self.lp)
        self.ldap_connections.append(samdb)
        return samdb


    def guess_a_dns_lookup(self):
        # XXX at some point do something sensible
        return ('example.com', 'A')

class Conversation(object):
    def __init__(self, start_time=None, endpoints=None):
        self.start_time = start_time
        self.endpoints = endpoints
        self.packets = []
        self.msg = random_colour_print()
        self.client_balance = 0.0

    def add_packet(self, packet):
        """Add a packet object to this conversation, making a local copy with
        a conversation-relative timestamp."""
        p = packet.copy()

        if self.start_time is None:
            self.start_time = p.timestamp

        if self.endpoints is None:
            self.endpoints = p.endpoints

        if p.endpoints != self.endpoints:
            raise FakePacketError("Conversation endpoints %s don't match"
                                  "packet endpoints %s" %
                                  (self.endpoints, p.endpoints))

        p.timestamp -= self.start_time

        if p.src == p.endpoints[0]:
            self.client_balance -= p.client_score()
        else:
            self.client_balance += p.client_score()

        self.packets.append(p)

    def add_short_packet(self, timestamp, p, extra, client=True):
        """Create a packet from a timestamp, and 'protocol:opcode' pair, and a
        (possibly empty) list of extra data. If client is True, assume
        this packet is from the client to the server.
        """
        protocol, opcode = p.split(':', 1)
        src, dest = self.guess_client_server()
        if not client:
            src, dest = dest, src

        desc = OP_DESCRIPTIONS.get((protocol, opcode), '')
        ip_protocol = IP_PROTOCOLS.get(protocol, '06')
        fields = [timestamp - self.start_time, ip_protocol,
                  '', src, dest,
                  protocol, opcode, desc]
        fields.extend(extra)
        p = Packet(fields)
        # XXX we're assuming the timestamp is already adjusted for
        # this conversation?
        # XXX should we adjust client balance for guessed packets?
        if p.src == p.endpoints[0]:
            self.client_balance -= p.client_score()
        else:
            self.client_balance += p.client_score()
        self.packets.append(p)

    def __str__(self):
        return ("<Conversation %s starting %.3f %d packets>" %
                (self.endpoints, self.start_time, len(self.packets)))

    def __iter__(self):
        return iter(self.packets)

    def __len__(self):
        return len(self.packets)

    def __cmp__(self, other):
        return self.start_time - other.start_time

    def get_duration(self):
        if len(self.packets) < 2:
            return 0
        return self.packets[-1].timestamp - self.packets[0].timestamp

    def replay_as_summary_lines(self):
        lines = []
        for p in self.packets:
            lines.append(p.as_summary(self.start_time))
        return lines

    def replay_in_fork_with_delay(self, start, context=None):
        t = self.start_time
        now = time.time() - start
        gap = t - now
        # we are replaying strictly in order, so it is safe to sleep
        # in the main process if the gap is big enough. This reduces
        # the number of concurrent threads, which allows us to make
        # larger loads.
        if gap > 0.15 and False:
            print >> sys.stderr, "sleeping for %f in main process" % (gap - 0.1)
            time.sleep(gap - 0.1)
            now = time.time() - start
            gap = t - now
            print >> sys.stderr, "gap is now %f" % gap

        pid = os.fork()
        if pid == 0:
            sleep_time = gap - SLEEP_OVERHEAD
            if sleep_time > 0:
                time.sleep(sleep_time)

            miss = t - (time.time() - start)
            self.msg("starting %s [miss %.3f]" % (self, miss))

            self.replay(context)
            os._exit(0)

        return pid

    def replay(self, context=None):
        start = time.time()
        for p in self.packets:
            now = time.time() - start
            gap = p.timestamp - now
            sleep_time = gap - SLEEP_OVERHEAD
            if sleep_time > 0:
                time.sleep(sleep_time)

            miss = p.timestamp - (time.time() - start)
            if context is None:
                self.msg("packet %s [miss %.3f pid %d]" % (p, miss, os.getpid()))
                continue

            p.play(self, context)

    def guess_client_server(self, server_clue=None):
        """Have a go at deciding who is the server and who is the client.
        returns (client, server)
        """
        a, b = self.endpoints

        if self.client_balance < 0:
            return (a, b)

        # in the absense of a clue, we will fall through to assuming
        # the lowest number is the server (which is usually true).

        if self.client_balance == 0 and server_clue == b:
            return (a, b)

        return (b, a)

    def add_dns_storm(self, dns_rate, duration):
        n = int(rate * duration)
        times = [random.uniform(0, duration) for i in range(n)]
        times.sort()
        for t in times:
            timestamp = self.start_time + t
            self.add_short_packet(timestamp, 'dns:0', [])

        self.packets.sort()


def ingest_summaries(files):
    dns_counts = defaultdict(int)
    packets = []
    for f in files:
        if isinstance(f, str):
            f = open(f)
        print >> sys.stderr, "Ingesting %s" % (f.name,)
        for line in f:
            p = Packet(line)
            if p.protocol == 'dns':
                dns_counts[p.opcode] += 1
            packets.append(Packet(line))
        f.close()

    if not packets:
        return [], 0

    start_time = min(p.timestamp for p in packets)
    last_packet = max(p.timestamp for p in packets)

    print >> sys.stderr, "gathering packets into conversations"
    conversations = OrderedDict()
    for p in packets:
        p.timestamp -= start_time
        c = conversations.get(p.endpoints)
        if c is None:
            c = Conversation()
            conversations[p.endpoints] = c
        c.add_packet(p)

    # This is obviously not correct, as many conversations will appear
    # to start roughly simultaneously at the beginning of the snapshot.
    # To which we say: oh well, so be it.
    duration = float(last_packet - start_time)
    mean_interval = len(conversations) / duration

    dns_rate = dns_counts['0'] / duration

    return conversations.values(), mean_interval, dns_rate


def guess_server_address(conversations):
    # we guess the most common address.
    addresses = Counter()
    for c in conversations:
        addresses.update(c.endpoints)
    if addresses:
        return addresses.most_common(1)[0]

def stringify_keys(x):
    y = {}
    for k, v in x.iteritems():
        k2 = '\t'.join(k)
        y[k2] = v
    return y


def unstringify_keys(x):
    y = {}
    for k, v in x.iteritems():
        t = tuple(str(k).split('\t'))
        y[t] = v
    return y


class TrafficModel(object):
    def __init__(self, n=3, dns_mode='count'):
        self.ngrams = {}
        self.query_details = {}
        self.n = n
        self.dns_mode = dns_mode
        self.dns_opcounts = defaultdict(int)
        self.cumulative_duration = 0.0
        self.conversation_rate = [0, 1]

    def learn(self, conversations):
        prev = 0.0
        cum_duration = 0.0
        key = (NON_PACKET,) * (self.n - 1)

        server = guess_server_address(conversations)

        if len(conversations) > 1:
            elapsed = conversations[1].start_time - conversations[0].start_time
            self.conversation_rate[0] += elapsed
            self.conversation_rate[0] += len(conversations)

        for c in conversations:
            client, server = c.guess_client_server(server)
            cum_duration += c.get_duration()
            key = (NON_PACKET,) * (self.n - 1)
            for p in c:
                if p.src != client:
                    continue

                if self.dns_mode != 'include' and p.protocol == 'dns':
                    self.dns_opcounts[p.opcode] += 1
                    continue

                elapsed = p.timestamp - prev
                prev = p.timestamp
                if elapsed > WAIT_THRESHOLD:
                    # add the wait as an extra state
                    wait = 'wait:%d' % (math.log(max(1.0,
                                                     elapsed * WAIT_SCALE)))
                    self.ngrams.setdefault(key, []).append(wait)
                    key = key[1:] + (wait,)

                short_p = p.as_packet_type()
                self.query_details.setdefault(short_p,
                                              []).append(tuple(p.extra))
                self.ngrams.setdefault(key, []).append(short_p)
                key = key[1:] + (short_p,)

        self.cumulative_duration += cum_duration
        # add in the end
        self.ngrams.setdefault(key, []).append(NON_PACKET)

    def save(self, f):
        ngrams = {}
        for k, v in self.ngrams.iteritems():
            k = '\t'.join(k)
            ngrams[k] = dict(Counter(v))

        query_details = {}
        for k, v in self.query_details.iteritems():
            query_details[k] = dict(Counter('\t'.join(x) if x else '-'
                                            for x in v))

        d = {
            'ngrams': ngrams,
            'query_details': query_details,
            'cumulative_duration': self.cumulative_duration,
            'conversation_rate': self.conversation_rate,
         }
        if self.dns_mode == 'count':
            d['dns'] = self.dns_opcounts

        if isinstance(f, str):
            f = open(f, 'w')

        json.dump(d, f, indent=2)

    def load(self, f):
        if isinstance(f, str):
            f = open(f)

        d = json.load(f)

        for k, v in d['ngrams'].iteritems():
            k = tuple(str(k).split('\t'))
            values = self.ngrams.setdefault(k, [])
            for p, count in v.iteritems():
                values.extend([str(p)] * count)

        for k, v in d['query_details'].iteritems():
            values = self.query_details.setdefault(str(k), [])
            for p, count in v.iteritems():
                if p == '-':
                    values.extend([()] * count)
                else:
                    values.extend([tuple(str(p).split('\t'))] * count)
        if 'dns' in d:
            self.dns_opcounts.update(d['dns'])

        self.cumulative_duration = d['cumulative_duration']
        self.conversation_rate = d['conversation_rate']

    def get_dns_rate(self):
        ops = self.dns_opcounts.get('0', 0)
        return ops / self.cumulative_duration

    def construct_conversation(self, timestamp=0.0, client=2, server=1,
                               hard_stop=None):
        c = Conversation(timestamp, (server, client))

        key = (NON_PACKET,) * (self.n - 1)

        while key in self.ngrams:
            p = random.choice(self.ngrams.get(key, NON_PACKET))
            if p == NON_PACKET:
                break
            if p in self.query_details:
                extra = random.choice(self.query_details[p])
            else:
                extra = []

            protocol, opcode = p.split(':', 1)
            if protocol == 'wait':
                log_wait_time = int(opcode) + random.random()
                timestamp += math.exp(log_wait_time) / WAIT_SCALE
            else:
                log_wait = random.uniform(*NO_WAIT_LOG_TIME_RANGE)
                timestamp += math.exp(log_wait)
                if hard_stop is not None and timestamp > hard_stop:
                    break
                c.add_short_packet(timestamp, p, extra)

            key = key[1:] + (p,)

        return c

    def generate_conversations(self, rate, duration):
        n = 1 + int(rate * self.conversation_rate[0] * duration /
                    self.conversation_rate[1])
        server = 1
        client = 2

        conversations = []
        for i in range(n):
            start = random.uniform(0, duration - 0.5)
            c = self.construct_conversation(start,
                                            client,
                                            server,
                                            hard_stop=duration)
            conversations.append(c)
            client += 1
        conversations.sort()
        return conversations

IP_PROTOCOLS = {
    'dns': '11',
    'rpc_netlogon': '06',
    'kerberos': '06',      # ratio 16248:258
    'smb': '06',
    'smb2': '06',
    'ldap': '06',
    'cldap': '11',
    'lsarpc': '06',
    'samr': '06',
    'dcerpc': '06',
    'epm': '06',
    'drsuapi': '06',
    'browser': '11',
    'smb_netlogon': '11',
    'srvsvc': '06',
    'nbns': '11',
}

OP_DESCRIPTIONS = {
    ('browser', '0x01'): 'Host Announcement (0x01)',
    ('browser', '0x02'): 'Request Announcement (0x02)',
    ('browser', '0x08'): 'Browser Election Request (0x08)',
    ('browser', '0x09'): 'Get Backup List Request (0x09)',
    ('browser', '0x0c'): 'Domain/Workgroup Announcement (0x0c)',
    ('browser', '0x0f'): 'Local Master Announcement (0x0f)',
    ('cldap', '3'): 'searchRequest',
    ('cldap', '5'): 'searchResDone',
    ('dcerpc', '0'): 'Request',
    ('dcerpc', '11'): 'Bind',
    ('dcerpc', '12'): 'Bind_ack',
    ('dcerpc', '13'): 'Bind_nak',
    ('dcerpc', '14'): 'Alter_context',
    ('dcerpc', '15'): 'Alter_context_resp',
    ('dcerpc', '16'): 'AUTH3',
    ('dcerpc', '2'): 'Response',
    ('dns', '0'): 'query',
    ('dns', '1'): 'response',
    ('drsuapi', '0'): 'DsBind',
    ('drsuapi', '12'): 'DsCrackNames',
    ('drsuapi', '13'): 'DsWriteAccountSpn',
    ('drsuapi', '1'): 'DsUnbind',
    ('drsuapi', '2'): 'DsReplicaSync',
    ('drsuapi', '3'): 'DsGetNCChanges',
    ('drsuapi', '4'): 'DsReplicaUpdateRefs',
    ('epm', '3'): 'Map',
    ('kerberos', ''): '',
    ('ldap', ''): '',
    ('ldap', '0'): 'bindRequest',
    ('ldap', '1'): 'bindResponse',
    ('ldap', '2'): 'unbindRequest',
    ('ldap', '3'): 'searchRequest',
    ('ldap', '4'): 'searchResEntry',
    ('ldap', '5'): 'searchResDone',
    ('ldap', ''): '*** Unknown ***',
    ('lsarpc', '14'): 'lsa_LookupNames',
    ('lsarpc', '15'): 'lsa_LookupSids',
    ('lsarpc', '39'): 'lsa_QueryTrustedDomainInfoBySid',
    ('lsarpc', '40'): 'lsa_SetTrustedDomainInfo',
    ('lsarpc', '6'): 'lsa_OpenPolicy',
    ('lsarpc', '76'): 'lsa_LookupSids3',
    ('lsarpc', '77'): 'lsa_LookupNames4',
    ('nbns', '0'): 'query',
    ('nbns', '1'): 'response',
    ('rpc_netlogon', '21'): 'NetrLogonDummyRoutine1',
    ('rpc_netlogon', '26'): 'NetrServerAuthenticate3',
    ('rpc_netlogon', '29'): 'NetrLogonGetDomainInfo',
    ('rpc_netlogon', '30'): 'NetrServerPasswordSet2',
    ('rpc_netlogon', '39'): 'NetrLogonSamLogonEx',
    ('rpc_netlogon', '40'): 'DsrEnumerateDomainTrusts',
    ('rpc_netlogon', '45'): 'NetrLogonSamLogonWithFlags',
    ('rpc_netlogon', '4'): 'NetrServerReqChallenge',
    ('samr', '16'): 'GetAliasMembership',
    ('samr', '17'): 'LookupNames',
    ('samr', '18'): 'LookupRids',
    ('samr', '19'): 'OpenGroup',
    ('samr', '1'): 'Close',
    ('samr', '25'): 'QueryGroupMember',
    ('samr', '34'): 'OpenUser',
    ('samr', '36'): 'QueryUserInfo',
    ('samr', '39'): 'GetGroupsForUser',
    ('samr', '3'): 'QuerySecurity',
    ('samr', '5'): 'LookupDomain',
    ('samr', '64'): 'Connect5',
    ('samr', '6'): 'EnumDomains',
    ('samr', '7'): 'OpenDomain',
    ('samr', '8'): 'QueryDomainInfo',
    ('smb', '0x04'): 'Close (0x04)',
    ('smb', '0x24'): 'Locking AndX (0x24)',
    ('smb', '0x2e'): 'Read AndX (0x2e)',
    ('smb', '0x32'): 'Trans2 (0x32)',
    ('smb', '0x71'): 'Tree Disconnect (0x71)',
    ('smb', '0x72'): 'Negotiate Protocol (0x72)',
    ('smb', '0x73'): 'Session Setup AndX (0x73)',
    ('smb', '0x74'): 'Logoff AndX (0x74)',
    ('smb', '0x75'): 'Tree Connect AndX (0x75)',
    ('smb', '0xa2'): 'NT Create AndX (0xa2)',
    ('smb2', '0'): 'NegotiateProtocol',
    ('smb2', '11'): 'Ioctl',
    ('smb2', '14'): 'Find',
    ('smb2', '16'): 'GetInfo',
    ('smb2', '18'): 'Break',
    ('smb2', '1'): 'SessionSetup',
    ('smb2', '2'): 'SessionLogoff',
    ('smb2', '3'): 'TreeConnect',
    ('smb2', '4'): 'TreeDisconnect',
    ('smb2', '5'): 'Create',
    ('smb2', '6'): 'Close',
    ('smb2', '8'): 'Read',
    ('smb_netlogon', '0x12'): 'SAM LOGON request from client (0x12)',
    ('smb_netlogon', '0x17'): ('SAM Active Directory Response - '
                               'user unknown (0x17)'),
    ('srvsvc', '16'): 'NetShareGetInfo',
    ('srvsvc', '21'): 'NetSrvGetInfo',
}


def expand_short_packet(p, timestamp, src, dest, extra):
    protocol, opcode = p.split(':', 1)
    desc = OP_DESCRIPTIONS.get((protocol, opcode), '')
    ip_protocol = IP_PROTOCOLS.get(protocol, '06')

    line = [timestamp, ip_protocol, '', src, dest, protocol, opcode, desc]
    line.extend(extra)
    return '\t'.join(line)


def replay(conversations, host=None, lp=None, creds=None,
           duration=None, dns_rate=None):
    if host is None:
        context = None
    else:
        context = ReplayContext(host, lp, creds)
    start = time.time()

    conversations.sort()

    if duration is not None:
        end = start + duration
    else:
        end = conversations[-1].packets[-1].timestamp + 1
        duration = end - start

    children = {}

    if dns_rate is not None:
        dns_hammer = conversations[0]
        dns_hammer.add_dns_storm(dns_rate, duration)

    for c in conversations:
        pid = c.replay_in_fork_with_delay(start, context)
        children[pid] = c

        pid, status = os.waitpid(-1, os.WNOHANG)
        if pid:
            c = children.pop(pid, None)
            print ("pid %d conversation %s finished early! %d in flight" %
                   (pid, c, len(children)))

        if (end is not None and time.time() >= end):
            break

    while children:
        time.sleep(0.01)
        pid, status = os.waitpid(-1, os.WNOHANG)
        #pid, status = os.wait()
        if pid:
            c = children.pop(pid, None)
            print ("process %d finished conversation %s; %d to go" %
                   (pid, c, len(children)))

        if (end is not None and time.time() >= end):
            break

    for s in (15, 15, 9):
        for pid in children:
            try:
                os.kill(pid, s)
            except OSError as e:
                if e.errno != 3: # don't fail if it has already died
                    raise
        time.sleep(1)
        end = time.time() + 1
        while children:
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid != 0:
                c = children.pop(pid, None)
                print "kill -%d %d KILLED conversation %s; %d to go" % (s, pid, c,
                                                                        len(children))
            if time.time() >= end:
                break

        if not children:
            break
        time.sleep(1)

    if children:
        print "%d children are missing" % len(children)
