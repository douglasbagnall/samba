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
