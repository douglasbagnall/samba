# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pprint import pprint
from cStringIO import StringIO

import samba.tests

from samba.emulate import traffic


TEST_FILE = 'testdata/traffic-sample-very-short.txt'

class TrafficEmulatorTests(samba.tests.TestCase):
    def setUp(self):
        self.model = traffic.TrafficModel()

    def tearDown(self):
        del self.model

    def test_parse_ngrams_dns_included(self):
        model = traffic.TrafficModel(dns_mode='include')
        f = open(TEST_FILE)
        conversations, interval, dns_rate = traffic.ingest_summaries([f])
        f.close()
        model.learn(conversations)
        expected_ngrams = {
            ('-', '-'): ['dns:0'],
            ('-', 'dns:0'): ['dns:0'],
            ('cldap:3', 'cldap:3'): ['cldap:3', 'wait:0'],
            ('cldap:3', 'wait:0'): ['dcerpc:11'],
            ('dcerpc:11', 'epm:3'): ['dcerpc:11'],
            ('dcerpc:11', 'rpc_netlogon:21'): ['epm:3'],
            ('dcerpc:11', 'rpc_netlogon:4'): ['rpc_netlogon:26'],
            ('dns:0', 'dns:0'): ['dns:0',
                                 'dns:0',
                                 'dns:0',
                                 'dns:0',
                                 'dns:0',
                                 'ldap:3',
                                 'wait:0'],
            ('dns:0', 'ldap:3'): ['wait:1'],
            ('dns:0', 'wait:0'): ['cldap:3'],
            ('epm:3', 'dcerpc:11'): ['rpc_netlogon:4'],
            ('epm:3', 'rpc_netlogon:29'): ['kerberos:'],
            ('kerberos:', 'ldap:3'): ['smb:0x72'],
            ('ldap:2', 'dns:0'): ['dns:0'],
            ('ldap:3', 'smb:0x72'): ['-'],
            ('ldap:3', 'wait:1'): ['ldap:2'],
            ('rpc_netlogon:21', 'epm:3'): ['rpc_netlogon:29'],
            ('rpc_netlogon:26', 'dcerpc:11'): ['rpc_netlogon:21'],
            ('rpc_netlogon:29', 'kerberos:'): ['ldap:3'],
            ('rpc_netlogon:4', 'rpc_netlogon:26'): ['dcerpc:11'],
            ('wait:0', 'cldap:3'): ['cldap:3'],
            ('wait:0', 'dcerpc:11'): ['epm:3'],
            ('wait:1', 'ldap:2'): ['dns:0']
        }
        expected_query_details = {
            'cldap:3': [('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', '')],
            'dcerpc:11': [(), (), ()],
            'dns:0': [(), (), (), (), (), (), (), (), ()],
            'epm:3': [(), ()],
            'kerberos:': [('',)],
            'ldap:2': [('', '', '', '', '', '', '')],
            'ldap:3': [('',
                        '',
                        '',
                        ('subschemaSubentry,dsServiceName,namingContexts,'
                         'defaultNamingContext,schemaNamingContext,'
                         'configurationNamingContext,rootDomainNamingContext,'
                         'supportedControl,supportedLDAPVersion,'
                         'supportedLDAPPolicies,supportedSASLMechanisms,'
                         'dnsHostName,ldapServiceName,serverName,'
                         'supportedCapabilities'),
                        '',
                        '',
                        ''),
                       ('2', 'DC,DC', '', 'cn', '', '', '')],
            'rpc_netlogon:21': [()],
            'rpc_netlogon:26': [()],
            'rpc_netlogon:29': [()],
            'rpc_netlogon:4': [()],
            'smb:0x72': [()]
        }
        self.maxDiff = 5000
        ngrams = {k: sorted(v) for k, v in model.ngrams.items()}
        details = {k: sorted(v) for k, v in model.query_details.items()}

        self.assertEqual(expected_ngrams, ngrams)
        self.assertEqual(expected_query_details, details)
        # We use a stringIO instead of a temporary file
        f = StringIO()
        model.save(f)

        model2 = traffic.TrafficModel(dns_mode='include')
        f.seek(0)
        model2.load(f)

        self.assertEqual(expected_ngrams, model2.ngrams)
        self.assertEqual(expected_query_details, model2.query_details)


    def test_parse_ngrams(self):
        f = open(TEST_FILE)
        conversations, interval, dns_rate = traffic.ingest_summaries([f])
        f.close()
        self.model.learn(conversations)
        #print 'ngrams'
        #pprint(self.model.ngrams, width=50)
        #print 'query_details'
        #pprint(self.model.query_details, width=55)
        expected_ngrams = {
            ('rpc_netlogon:4', 'rpc_netlogon:26'): ['dcerpc:11'],
            ('epm:3', 'dcerpc:11'): ['rpc_netlogon:4'],
            ('-', '-'): ['ldap:3'],
            ('dcerpc:11', 'epm:3'): ['dcerpc:11'], 
            ('rpc_netlogon:29', 'kerberos:'): ['ldap:3'], 
            ('cldap:3', 'cldap:3'): ['cldap:3', 'wait:0'], 
            ('ldap:3', 'smb:0x72'): ['-'], 
            ('epm:3', 'rpc_netlogon:29'): ['kerberos:'], 
            ('ldap:2', 'cldap:3'): ['cldap:3'], 
            ('kerberos:', 'ldap:3'): ['smb:0x72'], 
            ('ldap:3', 'wait:1'): ['ldap:2'], 
            ('wait:0', 'dcerpc:11'): ['epm:3'], 
            ('dcerpc:11', 'rpc_netlogon:4'): ['rpc_netlogon:26'], 
            ('wait:1', 'ldap:2'): ['cldap:3'], 
            ('cldap:3', 'wait:0'): ['dcerpc:11'], 
            ('rpc_netlogon:26', 'dcerpc:11'): ['rpc_netlogon:21'], 
            ('-', 'ldap:3'): ['wait:1'], 
            ('rpc_netlogon:21', 'epm:3'): ['rpc_netlogon:29'], 
            ('dcerpc:11', 'rpc_netlogon:21'): ['epm:3']
        }

        expected_query_details = {
            'cldap:3': [('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', '')],
            'dcerpc:11': [(), (), ()],
            'epm:3': [(), ()],
            'kerberos:': [('',)],
            'ldap:2': [('', '', '', '', '', '', '')],
            'ldap:3': [('',
                        '',
                        '',
                        ('subschemaSubentry,dsServiceName,namingContexts,'
                         'defaultNamingContext,schemaNamingContext,'
                         'configurationNamingContext,rootDomainNamingContext,'
                         'supportedControl,supportedLDAPVersion,'
                         'supportedLDAPPolicies,supportedSASLMechanisms,'
                         'dnsHostName,ldapServiceName,serverName,'
                         'supportedCapabilities'),
                        '',
                        '',
                        ''),
                       ('2', 'DC,DC', '', 'cn', '', '', '')],
            'rpc_netlogon:21': [()],
            'rpc_netlogon:26': [()],
            'rpc_netlogon:29': [()],
            'rpc_netlogon:4': [()],
            'smb:0x72': [()]
        }
        self.maxDiff = 5000
        ngrams = {k: sorted(v) for k, v in self.model.ngrams.items()}
        details = {k: sorted(v) for k, v in self.model.query_details.items()}
        
        self.assertEqual(expected_ngrams, ngrams)
        self.assertEqual(expected_query_details, details)
        # We use a stringIO instead of a temporary file
        f = StringIO()
        self.model.save(f)

        model2 = traffic.TrafficModel()
        f.seek(0)
        model2.load(f)

        self.assertEqual(expected_ngrams, model2.ngrams)
        self.assertEqual(expected_query_details, model2.query_details)
       
