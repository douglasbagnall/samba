# -*- encoding: utf-8 -*-
from collections import namedtuple


Datapoint = namedtuple('Datapoint',
                       'time, c_id, proto, op_id, duration, success, error')


def parser_v1(line):
    line = line.rstrip('\n')
    time, c_id, proto, op_id, duration, success, error = line.split('\t', 6)
    time = float(time)
    c_id = int(c_id)
    duration = float(duration)
    success = success == 'True'
    if error == '':
        error = None
    return Datapoint(time, c_id, proto, op_id, duration, success, error)


TIMING_FILE_PARSERS = {
    'time\tconv\tprotocol\ttype\tduration\tsuccessful\terror\n' : parser_v1
}


def get_file_parser(line):
    return TIMING_FILE_PARSERS[line]

SummaryLine = namedtuple('SummaryLine',
                         'time, ip_protocol, stream_id, src, dest, '
                         'proto, op_id, desc, has_extra')

def summary_parser(line):
    fields = line.rstrip('\n').split('\t')
    (timestamp,
     ip_protocol,
     stream_number,
     src,
     dest,
     protocol,
     opcode,
     desc) = fields[:8]

    timestamp = float(timestamp)
    src = int(src)
    dest = int(dest)
    has_extra = len(fields) > 8
    success = success == 'True'

    return SummaryLine(float(timestamp),
                       ip_protocol,
                       stream_number,
                       int(src),
                       int(dest),
                       protocol,
                       op_id,
                       desc, has_extra)
