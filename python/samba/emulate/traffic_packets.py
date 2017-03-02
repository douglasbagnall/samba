# Dispatch for various request types.
import sys

from samba.samdb import SamDB
from samba.net import Net
from samba.dcerpc import security, drsuapi, misc, nbt, lsa, drsblobs


def pass_verbosely():
    import traceback
    tb = traceback.extract_stack(limit=2)
    print "\033[48;5;19m" " doing nothing: %s " "\033[00m" % (tb[0][2])

def packet_browser_0x01(packet, conversation, context):  # Host Announcement (0x01) [625]
    pass_verbosely()

def packet_browser_0x02(packet, conversation, context):  # Request Announcement (0x02) [46]
    pass_verbosely()

def packet_browser_0x08(packet, conversation, context):  # Browser Election Request (0x08) [7182]
    pass_verbosely()

def packet_browser_0x09(packet, conversation, context):  # Get Backup List Request (0x09) [113]
    pass_verbosely()

def packet_browser_0x0c(packet, conversation, context):  # Domain/Workgroup Announcement (0x0c) [31]
    pass_verbosely()

def packet_browser_0x0f(packet, conversation, context):  # Local Master Announcement (0x0f) [116]
    pass_verbosely()

def packet_cldap_3(packet, conversation, context):  # searchRequest
    net = Net(creds=context.creds, lp=context.lp)
    net.finddc(domain=context.lp.get('realm'),
               flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE)


def packet_dcerpc_0(packet, conversation, context):  # Request [58315]
    c = context.get_dcerpc_connection()
    c.request(0, chr(0) * 4)

def packet_dcerpc_11(packet, conversation, context):  # Bind [4060]
    #12345678-1234-abcd-ef00-01234567cffb

    context.get_dcerpc_connection(True)

#def packet_dcerpc_12(packet, conversation, context):  # Bind_ack [4058]
#    pass_verbosely()

#def packet_dcerpc_13(packet, conversation, context):  # Bind_nak [2]
#    pass_verbosely()

def packet_dcerpc_14(packet, conversation, context):  # Alter_context [794]
    pass_verbosely()

def packet_dcerpc_15(packet, conversation, context):  # Alter_context_resp [793]
    pass_verbosely()

def packet_dcerpc_16(packet, conversation, context):  # AUTH3 [2]
    pass_verbosely()

#def packet_dcerpc_2(packet, conversation, context):  # Response [61738]
#    pass_verbosely()


def packet_dns_0(packet, conversation, context):  # query

    name, rtype = context.guess_a_dns_lookup()
    cmd = ['dig', '@%s' % context.server, name, rtype]

    # using plain Popen() istead of call() is like P_NOWAIT, meaning
    # the call happens in a background fork and we don't wait for it.
    subprocess.Popen(cmd)

#def packet_dns_1(packet, conversation, context):  # response
#    pass_verbosely()

def packet_drsuapi_0(packet, conversation, context):  # DsBind
    context.get_drsuapi_connection_pair(True)


NAME_FORMATS = [getattr(drsuapi, _x) for _x in dir (drsuapi)
                if 'NAME_FORMAT' in _x]

def packet_drsuapi_12(packet, conversation, context):  # DsCrackNames [1885]
    drs, handle = context.get_drsuapi_connection_pair()

    names = drsuapi.DsNameString()
    names.str = contextserver

    req = drsuapi.DsNameRequest1()
    req.format_flags = 0
    req.format_offered = 7
    req.format_desired = random.choice(name_formats)
    req.codepage = 1252
    req.language = 1033  # German, I think
    req.format_flags = 0
    req.format_offered = opts.informat
    req.format_desired = opts.outformat
    req.count = 1
    req.names = [names]

    (result, ctr) = drs.DsCrackNames(handle, 1, req)

def packet_drsuapi_13(packet, conversation, context):  # DsWriteAccountSpn [236]
    pass_verbosely()

def packet_drsuapi_1(packet, conversation, context):  # DsUnbind [1946]
    drs, handle = context.get_drsuapi_connection_pair(unbind=True)
    drs.DsUnBind(handle)

def packet_drsuapi_2(packet, conversation, context):  # DsReplicaSync [920]
    pass_verbosely()

def packet_drsuapi_3(packet, conversation, context):  # DsGetNCChanges [1226]
    pass_verbosely()

def packet_drsuapi_4(packet, conversation, context):  # DsReplicaUpdateRefs [1320]
    pass_verbosely()

def packet_epm_3(packet, conversation, context):  # Map [4442]
    pass_verbosely()

# ignoring 16506 kerberos

# ignoring 48 ldap

def packet_ldap_0(packet, conversation, context):  # bindRequest [5029]
    context.get_ldap_connection(new=True)

#def packet_ldap_1(packet, conversation, context):  # bindResponse [5029]
#    pass_verbosely()

def packet_ldap_2(packet, conversation, context):  # unbindRequest
    # pop the last one off -- most likely we're in a bind/unbind ping.
    del context.ldap_connections[-1:]

def packet_ldap_3(packet, conversation, context):  # searchRequest
    "$scope $base_object $ldap_filter $ldap_attributes $extra $extra_desc $oid"
    # try to use a connection that has some kind of creds

    (scope, dn_sig, filter, attrs, extra, desc, oid) = packet.extra

    samdb = context.get_ldap_connection()
    dn = context.get_matching_dn(dn_sig)

    print >>sys.stderr, dn_sig, dn
    res = samdb.search(dn,
                       scope=int(scope),
                       attrs=attrs.split(','))


#def packet_ldap_4(packet, conversation, context):  # searchResEntry [31]
#    pass_verbosely()

#def packet_ldap_5(packet, conversation, context):  # searchResDone [10245]
#    pass_verbosely()

# ignoring ldap # Unknown *** [94943]

def packet_lsarpc_14(packet, conversation, context):  # lsa_LookupNames [44]
    c = context.get_lsarpc_connection()


    pass_verbosely()

def packet_lsarpc_15(packet, conversation, context):  # lsa_LookupSids [38]
    pass_verbosely()

def packet_lsarpc_39(packet, conversation, context):  # lsa_QueryTrustedDomainInfoBySid
    c = context.get_lsarpc_connection()

    objectAttr = lsa.ObjectAttribute()

    pol_handle = c.OpenPolicy2(u'', objectAttr,
                               security.SEC_FLAG_MAXIMUM_ALLOWED)

    domsid = security.dom_sid(context.ldb.get_domain_sid())

    #c.QueryTrustedDomainInfoBySid(pol_handle, domsid

    pass_verbosely()

def packet_lsarpc_40(packet, conversation, context):  # lsa_SetTrustedDomainInfo [12]
    pass_verbosely()

def packet_lsarpc_6(packet, conversation, context):  # lsa_OpenPolicy [2]
    pass_verbosely()

def packet_lsarpc_76(packet, conversation, context):  # lsa_LookupSids3 [2119]
    pass_verbosely()

def packet_lsarpc_77(packet, conversation, context):  # lsa_LookupNames4 [3108]
    pass_verbosely()

def packet_nbns_0(packet, conversation, context):  # query [6529]
    pass_verbosely()

def packet_nbns_1(packet, conversation, context):  # response [16]
    pass_verbosely()

def packet_rpc_netlogon_21(packet, conversation, context):  # NetrLogonDummyRoutine1 [202]
    pass_verbosely()

def packet_rpc_netlogon_26(packet, conversation, context):  # NetrServerAuthenticate3 [257]
    pass_verbosely()

def packet_rpc_netlogon_29(packet, conversation, context):  # NetrLogonGetDomainInfo [531]
    pass_verbosely()

def packet_rpc_netlogon_30(packet, conversation, context):  # NetrServerPass_Verbosely()wordSet2 [8]
    pass_verbosely()

def packet_rpc_netlogon_39(packet, conversation, context):  # NetrLogonSamLogonEx [4331]
    pass_verbosely()

def packet_rpc_netlogon_40(packet, conversation, context):  # DsrEnumerateDomainTrusts [18]
    pass_verbosely()

def packet_rpc_netlogon_45(packet, conversation, context):  # NetrLogonSamLogonWithFlags [7]
    pass_verbosely()

def packet_rpc_netlogon_4(packet, conversation, context):  # NetrServerReqChallenge [186]
    pass_verbosely()

def packet_samr_16(packet, conversation, context):  # GetAliasMembership [352]
    pass_verbosely()

def packet_samr_17(packet, conversation, context):  # LookupNames [236]
    pass_verbosely()

def packet_samr_18(packet, conversation, context):  # LookupRids [114]
    pass_verbosely()

def packet_samr_19(packet, conversation, context):  # OpenGroup [8]
    pass_verbosely()

def packet_samr_1(packet, conversation, context):  # Close [1204]
    pass_verbosely()

def packet_samr_25(packet, conversation, context):  # QueryGroupMember [8]
    pass_verbosely()

def packet_samr_34(packet, conversation, context):  # OpenUser [240]
    pass_verbosely()

def packet_samr_36(packet, conversation, context):  # QueryUserInfo [126]
    pass_verbosely()

def packet_samr_39(packet, conversation, context):  # GetGroupsForUser [236]
    pass_verbosely()

def packet_samr_3(packet, conversation, context):  # QuerySecurity [122]
    pass_verbosely()

def packet_samr_5(packet, conversation, context):  # LookupDomain [350]
    pass_verbosely()

def packet_samr_64(packet, conversation, context):  # Connect5 [360]
    pass_verbosely()

def packet_samr_6(packet, conversation, context):  # EnumDomains [350]
    pass_verbosely()

def packet_samr_7(packet, conversation, context):  # OpenDomain [596]
    pass_verbosely()

def packet_samr_8(packet, conversation, context):  # QueryDomainInfo [228]
    pass_verbosely()

def packet_smb_0x04(packet, conversation, context):  # Close (0x04) [78]
    pass_verbosely()

def packet_smb_0x24(packet, conversation, context):  # Locking AndX (0x24) [2]
    pass_verbosely()

def packet_smb_0x2e(packet, conversation, context):  # Read AndX (0x2e) [89]
    pass_verbosely()

def packet_smb_0x32(packet, conversation, context):  # Trans2 (0x32) [595]
    pass_verbosely()

def packet_smb_0x71(packet, conversation, context):  # Tree Disconnect (0x71) [92]
    pass_verbosely()

def packet_smb_0x72(packet, conversation, context):  # Negotiate Protocol (0x72) [1340]
    pass_verbosely()

def packet_smb_0x73(packet, conversation, context):  # Session Setup AndX (0x73) [88]
    pass_verbosely()

def packet_smb_0x74(packet, conversation, context):  # Logoff AndX (0x74) [88]
    pass_verbosely()

def packet_smb_0x75(packet, conversation, context):  # Tree Connect AndX (0x75) [92]
    pass_verbosely()

def packet_smb_0xa2(packet, conversation, context):  # NT Create AndX (0xa2) [92]
    pass_verbosely()

def packet_smb2_0(packet, conversation, context):  # NegotiateProtocol [4111]
    # we do a smb2_connect_ext to get:
    #  negprot     0
    #  sesssetup   1
    #  treeconnect 3
    pass_verbosely()

def packet_smb2_11(packet, conversation, context):  # Ioctl [5380]
    pass_verbosely()

def packet_smb2_14(packet, conversation, context):  # Find [2256]
    pass_verbosely()

def packet_smb2_16(packet, conversation, context):  # GetInfo [3038]
    pass_verbosely()

def packet_smb2_18(packet, conversation, context):  # Break [459]
    pass_verbosely()

def packet_smb2_1(packet, conversation, context):  # SessionSetup [2870]
    pass_verbosely()

def packet_smb2_2(packet, conversation, context):  # SessionLogoff [2815]
    pass_verbosely()

def packet_smb2_3(packet, conversation, context):  # TreeConnect [3434]
    pass_verbosely()

def packet_smb2_4(packet, conversation, context):  # TreeDisconnect [3400]
    pass_verbosely()

def packet_smb2_5(packet, conversation, context):  # Create [14527]
    pass_verbosely()

def packet_smb2_6(packet, conversation, context):  # Close [13713]
    pass_verbosely()

def packet_smb2_8(packet, conversation, context):  # Read [14256]
    pass_verbosely()

def packet_smb_netlogon_0x12(packet, conversation, context):  # SAM LOGON request from client (0x12) [20]
    pass_verbosely()

def packet_smb_netlogon_0x17(packet, conversation, context):  # SAM Active Directory Response - user unknown (0x17) [19]
    pass_verbosely()

def packet_srvsvc_16(packet, conversation, context):  # NetShareGetInfo [204]
    pass_verbosely()

def packet_srvsvc_21(packet, conversation, context):  # NetSrvGetInfo [32]
    pass_verbosely()
