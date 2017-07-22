# -*- encoding: utf-8 -*-
# Functions for generating reports from the traffic emulator results.
#
# Copyright (C) Catalyst IT Ltd 2017
#
# Catalyst's contribution mostly by Douglas Bagnall
# <douglas.bagnall@catalyst.net.nz>
#
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
    'time\tconv\tprotocol\ttype\tduration\tsuccessful\terror\n': parser_v1
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

    return SummaryLine(float(timestamp),
                       ip_protocol,
                       stream_number,
                       int(src),
                       int(dest),
                       protocol,
                       opcode,
                       desc, has_extra)
