#! /usr/bin/env python
# -*- coding: utf-8 -*

import re
import csv
import sys
import argparse

from decimal import Decimal
import xml.etree.ElementTree as ET

from pyparsing import *
from struct import unpack
from subprocess import Popen, PIPE, STDOUT


__author__    = "Andrey Kashirin <support@sysqual.net>"
__date__      = "2018-10-31 15:11:01 MSK"
__program__   = "xdr-tester"
__version__   = "1.0"


TSHARK_PATH = "/usr/bin/tshark"

BINOP_SG =          "< == > >= <= !="
CMPOPS_SG = "and or " + BINOP_SG
CMPOPS_FN = "land lor lt eq gt ge le ne"
def change_token(str, location, tokens):
    tl = list(tokens)
    for sg in CMPOPS_SG.split():
        if sg in tl:
            idx = tl.index(sg)
            func = CMPOPS_FN.split()[ CMPOPS_SG.split().index(sg) ]
            tl = [func] + [ change_token(str, location, tl[:idx]) ] + [tl[idx+1:] ]
    return tl


LPAR,RPAR,COMMA,SEMICLN,ASTERISK = map(Suppress, '(),;*')
and_, or_ = map(CaselessKeyword, "and or".split())
realNum = pyparsing_common.real()
intNum = pyparsing_common.signed_integer()
string = dblQuotedString | quotedString
number = realNum | intNum
rval = number | string
ident = ( number | ASTERISK | Combine( Word( alphanums + "_")) ).setName('ident')
sysvar = Combine("$"+ Word( alphanums + "_")).setName('sysvar')
wsfilter = Combine(ident + ZeroOrMore( Combine("." + ident) ) ).setName('filter')
binop = oneOf(BINOP_SG + " eq ne lt le gt ge", caseless=True)
#inner_expr = 
#rExpr =  ("cst" + LPAR + Word(nums) + RPAR).setName('rexpr')
fldFunc = oneOf("first last", caseless=True)
lgcFunc = oneOf("if ifnull lor land any", caseless=True)
cmdFunc = oneOf("eq gt lt le ge ne", caseless=True)
strFunc = oneOf("strrlike strsub", caseless=True)
aggrFunc = oneOf("sum count", caseless=True)
pduFunc = oneOf("way protocol message pdumsg tsdiff", caseless=True)
funcNames = (fldFunc | lgcFunc | strFunc | aggrFunc | pduFunc).setName('fname')

expression = Forward()

genfunc = (funcNames +
          LPAR +
            Group(
                (expression).setParseAction(change_token)
                 ) + 
            ZeroOrMore(SEMICLN + (Group(expression))) +
          RPAR
        ).setName('func')

operand = ( (sysvar | genfunc | wsfilter) + Optional(binop + rval) ).setName("op")
expression << (operand + ZeroOrMore( ( and_ | or_ ) + expression)).setParseAction(change_token)


#~ expression.runTests("""
        #~ $linkid
        #~ first(frame.time)
        #~ count(*)
        #~ nop(enrich.db)
        #~ sip.from.user or if(way(pdu.toward);*;count(*)) or 2
        #~ if(way(pdu.toward);*;count(*))
        #~ if( strrlike(sip.From)=='sip:.' ;strsub(last(sip.from.user); 6)   ;    strsub(last(sip.from.user); 5)   )
        #~ if( last(sip.from.user) or sip.from.user>=2;  if( strrlike(last(sip.From) ; strsub(last(sip.from.user); 6); strsub(last(sip.from.user); 5)));*)
        #~ first(if(message(*)==9 or message(*)==12 or message(*)==16;frame.time_epoch;*))
        #~ """)

#~ sys.exit(0)

PROTOS = dict(
    isup=1,
    bicc=3,
    sip=2,
    gtp=30,
    gtpv2=31,
)


class Evaluator(object):

    aggr_hash = {}

    def aggregative(func):
        def wrapper(*args, **kwargs):
            fn = func.func_name
            self = args[0]
            arg = args[1]
            if fn not in self.aggr_hash:
                self.aggr_hash[fn] = {}
            if arg not in self.aggr_hash[fn]:
                self.aggr_hash[fn][arg] = None
            return func(*args, **kwargs)
        return wrapper

    def func_eq(self, expression, value):
        leval = str(self.eval_expr(expression[0], value))
        reval = str(self.eval_expr(expression[1], value))
        return leval == reval

    def func_lgc_and(self, expression, value):
        for expr in expression:
            expr = self.eval_expr(expr, value)
            if expr is None or not expr:
                return False
        return True

    def func_lgc_or(self, expression, value):
        for expr in expression:
            expr = self.eval_expr(expr, value)
            if expr is not None:
                return expr
        return False

    def func_lgc_if(self, expression, value):
        expr = self.eval_expr(expression[0], value)
        if expr is not None and expr:
            return self.eval_expr(expression[1], value)
        else:
            return self.eval_expr(expression[2], value)

    def func_lgc_ifnull(self, expression, value):
        expr = self.eval_expr(expression[0], value)
        if expr is not None and expr:
            return expr
        return self.eval_expr(expression[1], value)

    @aggregative
    def func_first(self, expression, value):
        if self.aggr_hash['func_first'][expression] is None:
            _val = self.eval_expr(expression, value)
            self.aggr_hash['func_first'][expression] = _val
        return self.aggr_hash['func_first'][expression]

    @aggregative
    def func_count(self, expression, value):
        if self.aggr_hash['func_count'][expression] is None:
            self.aggr_hash['func_count'][expression] = 0
        self.aggr_hash['func_count'][expression] += 1
        return self.aggr_hash['func_count'][expression]

    @aggregative
    def func_sum(self, expression, value):
        if self.aggr_hash['func_sum'][expression] is None:
            self.aggr_hash['func_sum'][expression] = 0
        try:
            _val = self.eval_expr(expression, value)
            self.aggr_hash['func_sum'][expression] += int(_val)
        except:
            eprint("%s is not an int" % _val)
        return self.aggr_hash['func_sum'][expression]

    @aggregative
    def func_last(self, expression, value):
        _val = self.eval_expr(expression, value)
        if _val is not None:
            self.aggr_hash['func_last'][expression] = _val
        return self.aggr_hash['func_last'][expression]

    def func_pdu_protocol(self, expression, value):
        return self.protocol

    def func_pdu_message(self, expression, value):
        return self.message

    def func_pdu_tsdiff(self, expression, value):
        leval = self.eval_expr(expression[0], value)
        reval = self.eval_expr(expression[1], value)
        if leval is None or reval is None:
            return None
        return Decimal(leval) - Decimal(reval)

    def func_pdu_pdumsg(self, expression, value):
        pdu_nm = int(self.eval_expr(expression[0], value))
        result = None
        first = True
        if len(expression) == 2 and expression[1]=='pdu.last':
            first = False
        for pdu in self.pdus:
            if pdu.message == pdu_nm:
                result = pdu
                if first:
                    return result
        return result

    def func_pdu_direction(self, expression, value):
        if not isinstance(expression[0], str):
            return False
        clause = expression[0]
        if clause == "pdu.toward":
            if self.pdus[0].mtp3_opc is not None:
                pdu_from = self.extract_from_decoding("mtp3.opc")
                if pdu_from is not None:
                    pdu_to = self.extract_from_decoding("mtp3.dpc")
                if (pdu_from == self.pdus[0].mtp3_opc) and\
                (pdu_to == self.pdus[0].mtp3_dpc):
                    return True
            else:
                pdu_from = self.extract_from_decoding("ip.src")
                pdu_to = self.extract_from_decoding("ip.dst")
                if (pdu_from == self.pdus[0].ip_src) and\
                (pdu_to == self.pdus[0].ip_dst):
                    return True
        return False

    def eval_expr(self, expression, value):
        result = value
        try:
            if expression[0] == '':
                return None
            expr = expression[0]
            if len(expression) >= 2:
                args = expression[1]
                if len(expression) > 2:
                    args = expression[1:]
                if expr in self._token2func:
                    result = self._token2func[expr](args, value)
            else:
                if isinstance(expr, str):
                    if "'" in expr:
                        #~ string constant
                        return expr.replace("'","")
                    else:
                        if expr.isdigit():
                            return expr
                        result = self.extract_from_decoding(expr)
                elif isinstance(expr, int):
                    return expr
        except:
            eprint("eval_expr failed for expression=%s value=%s"
                   " message %s" % (expression, value, self.message))
        return result

    def reset(self, protocol, message):
        self.protocol = protocol
        self.message = message

    def __init__(self, extract_from_decoding, pdus):
        self.extract_from_decoding = extract_from_decoding
        self.pdus = pdus
        self._token2func = {
            "first": self.func_first,
            "last": self.func_last,
            "lor": self.func_lgc_or,
            "any": self.func_lgc_or,
            "land": self.func_lgc_and,
            "if": self.func_lgc_if,
            "ifnull": self.func_lgc_ifnull,
            "sum": self.func_sum,
            "count": self.func_count,
            "way": self.func_pdu_direction,
            "protocol": self.func_pdu_protocol,
            "message": self.func_pdu_message,
            "pdumsg": self.func_pdu_pdumsg,
            "tsdiff": self.func_pdu_tsdiff,
            "eq": self.func_eq,
        }

    def get_pkt_ts(self):
        return self.extract_from_decoding('timestamp', item='value')


def eprint(msg):
    if not isinstance(msg, str):
        try:
            msg = str(msg)
        except:
            msg = "eprint: not str instance passed. Failed to convert"
    sys.stderr.write(msg + '\n')


class XDRField(object):
    name = None
    expression = None
    value = None

    def __init__(self, name, text, value=None):
        self.name = name
        self.value = None
        try:
            self.expression = expression.parseString(text, parseAll=True)
        except:
            expression.runTests(text)
            #~ eprint("Failed to parse expression %s." % text)

    def recycle(self):
        self.value = None

    def __repr__(self):
        return "%s = '%s'" % (self.name, self.value)


class PDU(object):
    timestamp = None
    message = None
    ip_src = None
    ip_dst = None
    mtp3_opc = None
    mtp3_dpc = None

    def __init__(self, message, ts, ip_src, ip_dst,
                       mtp3_opc=None, mtp3_dpc=None):
        self.message = message
        try:
            self.timestamp = Decimal(ts)
        except:
            raise Exception("Timestamp for %s is not float" % ts)
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.mtp3_opc = mtp3_opc
        self.mtp3_dpc = mtp3_dpc

    def __repr__(self):
        if self.mtp3_opc is not None:
            return "%s %s->%s %s" % (self.timestamp, self.mtp3_opc,
                                     self.mtp3_opc, self.message)
        else:
            return "%s %s->%s %s" % (self.timestamp, self.ip_src,
                                     self.ip_dst, self.message)


class XDRTester(object):
    Fields = []
    Pdus = []
    cXMLDecoding = None
    pcap_file = None
    curr_fhdr = None

    def extract_from_decoding(self, filter, item='show'):
        expr = ".//*[@name='%s']" % filter
        leaf = self.cXMLDecoding.find(expr)
        if leaf is None:
            return
        attrib = leaf.attrib
        if attrib and item in attrib:
            return attrib[item]
        return

    def get_app_protocol(self):
        wsprotos = self.extract_from_decoding("frame.protocols")
        if 'udp' in wsprotos:
            if 'sip' in wsprotos:
                return PROTOS['sip']
            elif 'gtpv2' in wsprotos:
                return PROTOS['gtpv2']
            elif 'gtp' in wsprotos:
                return PROTOS['gtp']
        elif 'sctp' in wsprotos:
            if 'isup' in wsprotos:
                return PROTOS['isup']
            elif 'bicc' in wsprotos:
                return PROTOS['bicc']
        
    def get_pdu_message(self, protocol):
        protocol = self.get_app_protocol()
        if protocol == PROTOS['isup'] or protocol == PROTOS['bicc']:
            return int(self.extract_from_decoding("isup.message_type"))
        elif protocol == PROTOS['sip']:
            return int(self.extract_from_decoding("sip.Status-Code"))-15

    def _get_next_pkt(self):
        print("sctp dechunking shall be applied here")
        rhdr = self.pcap_file.read(16)
        if len(rhdr) != 16:
            return None
        ts_sec, ts_usec, incl_len, orig_len = unpack('IIII', rhdr)
        pkt = self.pcap_file.read(incl_len)
        if len(pkt) != incl_len:
            return None
        return rhdr + pkt

    def _get_tshark_proc(self, pkt):
        args = [TSHARK_PATH, '-T', 'pdml', '-Q', '-r', '-']
        tshart = Popen((args), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        tshart_res = tshart.communicate(input=self.curr_fhdr + pkt)
        return tshart_res

    def get_next_decoding(self):
        if not self.pcap_file:
            self.pcap_file = open(self.args.pcap, "rb")
            self.curr_fhdr = self.pcap_file.read(24)
        pkt = self._get_next_pkt()
        if not pkt:
            return (None, None)
        result = self._get_tshark_proc(pkt)
        return result

    def fillXDR(self, decoding):
        self.cXMLDecoding = ET.fromstring(decoding)
        protocol = self.get_app_protocol()
        message = self.get_pdu_message(protocol)
        self.evaluator.reset(protocol, message)
        self.Pdus.append(PDU(
                    message = message,
                    ts = self.evaluator.get_pkt_ts(),
                    ip_src = self.extract_from_decoding("ip.src"),
                    ip_dst = self.extract_from_decoding("ip.dst"),
                    mtp3_opc = self.extract_from_decoding("mtp3.opc"),
                    mtp3_dpc = self.extract_from_decoding("mtp3.dpc"),
                            )
                        )
        #~ cts = self._get_pkt_ts()
        for field in self.Fields:
            if not field.expression:
                continue
            if field.name == 'Media Src address IPv6':
                print(protocol, message)
                #~ import pdb; pdb.set_trace()
                pass
            field.value = self.evaluator.eval_expr(field.expression, field.value)
            

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description=__doc__,
            epilog="Report bugs to %s" % __author__
        )
        self.parser.add_argument(
            "-v", "--version", action="store_true",
            help="Print version and exit"
        )
        self.parser.add_argument(
            "--pcap", metavar="PCAPFILE", type=str,
            help="path to pcap file"
        )
        self.parser.add_argument(
            "--xdr", metavar="XDRFILE", type=str,
            help="path to xdr file"
        )
        self.parser.add_argument(
            "-d", "--delimiter", metavar="CSVDEL", type=str,
            default=",", dest='delm',
            help="csv field delimiter"
        )
        self.parser.add_argument(
            "-q", "--quotechar", metavar="CSVQUOT", type=str,
            default='/', dest='quote',
            help="csv field delimiter"
        )
        self.parser.add_argument(
            "-s", "--startframe", metavar="STARTFRAME", type=int,
            default=1, dest='stftrm',
            help="Start analysis from frame nb (1-based)"
        )
        self.parser.add_argument(
            "-l", "--pcaplimit", metavar="PCAPLIMIT", type=int,
            default=100, dest='plmt',
            help="number of pkts to read"
        )

    def main(self, cli_args):
        self.args = self.parser.parse_args(cli_args)
        if self.args.version:
            print '%s' % __version__
            return 0
        if not self.args.xdr or not self.args.pcap:
            self.parser.print_usage()
            return 0
        with open(self.args.xdr, 'rb') as csvfile:
            xdrreader = csv.reader(csvfile,
                                    delimiter=self.args.delm,
                                    quotechar=self.args.quote)
            fst_line = True
            for row in xdrreader:
                if fst_line:
                    fst_line = False
                    continue
                self.Fields.append(XDRField(row[1], row[3]))
        for i in range(1, self.args.stftrm):
            decoding, error = self.get_next_decoding()
        self.evaluator = Evaluator(self.extract_from_decoding,
                                   self.Pdus)
        for i in range(0, self.args.plmt):
            decoding, error = self.get_next_decoding()
            if decoding is None:
                break
            decoding = decoding[decoding.find('<?xml'):]
            self.fillXDR(decoding)
        for field in self.Fields:
            print(field)
        for pdu in self.Pdus:
            print(pdu)


if __name__ == "__main__":
    app = XDRTester()
    app.main(sys.argv[1:])
