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

DARK_YELLOW = "\033[00;33m"
MAGENTA     = "\033[01;35m"
DARK_CYAN   = "\033[00;36m"


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


def ascii_histogram_h(labels, values, log=False, colour='',
                      unicode_graphics=False, height=24):
    print values

    if log:
        plot_values = [math.log(x) for x in values]
    else:
        plot_values = values

    highest = max(plot_values)
    lowest = min(plot_values)
    scale = float(height) / highest

    if '\033' in colour:
        colour_off = "\033[00m"
    else:
        colour_off = ''

    portions = [' ']
    if unicode_graphics:
        portions.extend(unichr(x).encode('utf8') for x in range(9601, 9609))
        down_line = '│'
        corner_line = '╰'
        h_line = '─'
    else:
        portions.extend('....####')
        down_line, corner_line, h_line = '|+-'

    heights = [scale * x for x in plot_values]
    plot_top = max(heights)

    if lowest > 30 and highest < 1e6:
        tick_format = '%10.0f'
    elif lowest > 0.3:
        tick_format = '%10.1f'
    elif lowest > 0.03:
        tick_format = '%10.2f'
    else:
        tick_format = '%10.1g'

    for i in range(height, 0, -1):
        if i & 1 == 0:
            val = (highest * i / float(height))
            if log:
                val = math.exp(log)
            tick = tick_format % val
        else:
            tick = ''
        row = []
        for h in heights:
            if int(h) > i:
                row.append(portions[8])
            elif h > i:
                row.append(portions[int((i - h) * 9)])
                #row.append(str(int((h - i) * 9)))
            else:
                row.append(portions[0])
        row = ''.join(row)
        print '%10s %s%s%s' % (tick, colour, row, colour_off)
    row = ''.join([portions[8] if h > 1 else portions[h != 0]
                   for h in heights])
    print '%10s %s%s%s' % (0, colour, row, colour_off)

    n = len(values)
    print '%10s %s' % (' ', down_line * n)
    for v, label in reversed(zip(values, labels)):
        n -= 1
        print '%10s %s%s%s%s %.1f %s%s%s' % (' ', down_line * n,
                                             corner_line,
                                             h_line, h_line,
                                             v,
                                             colour, label,
                                             colour_off)
