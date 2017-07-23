# -*- encoding: utf-8 -*-
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

import samba.tests

from samba.emulate import traffic_report

TEST_DATA = [ # wikipedia: List of most isolated mountains of Switzerland
    ("Piz Bernina", 4049, 137.8, 2234),
    ("Monte Rosa", 4634, 78.3, 2165),
    ("Finsteraarhorn", 4274, 51.7, 2280),
    ("Chasseral", 1606, 49.5, 666),
    ("Tödi", 3614, 42.1, 1570),
    ("Mont Tendre", 1679, 38.7, 451),
    ("Rheinwaldhorn", 3402, 35.1, 1337),
    ("Le Chasseron", 1607, 32.0, 590),
    ("Schesaplana", 2964, 30.3, 826),
    ("Ringelspitz", 3248, 29.8, 844),
    ("Hasenmatt", 1445, 29.6, 618),
    ("Grand Combin", 4314, 26.4, 1517),
    ("Säntis", 2502, 25.7, 2021),
    ("Piz Linard", 3010, 24.9, 1027),
    ("Piz Kesch", 3418, 22.9, 1503),
    ("Wildhorn", 3248, 22.9, 978),
    ("Dammastock", 3630, 21.6, 1466),
]

TEST_FILE = 'testdata/traffic-sample-very-short.txt'

class TrafficEmulatorTests(samba.tests.TestCase):
    #def setUp(self):
    #    pass

    #def tearDown(self):
    #    pass

    def test_ascii_histogram_h(self):
        labels, v1, v2, v3 = zip(*sorted(TEST_DATA))
        traffic_report.ascii_histogram_h(labels, v2)
        traffic_report.ascii_histogram_h(labels, [x * y for x, y in zip(v1, v2)],
                                         unicode_graphics=True)
        
        traffic_report.ascii_histogram_h(labels, v3,
                                         unicode_graphics=True, height=10)
        
    def test_ascii_histogram_h_colour(self):
        labels, v1, v2, v3 = zip(*TEST_DATA)

        traffic_report.ascii_histogram_h(labels, v1,
                                         colour=traffic_report.DARK_YELLOW)
        traffic_report.ascii_histogram_h(labels, [x * y for x, y in zip(v1, v2)],
                                         colour=traffic_report.MAGENTA)
        traffic_report.ascii_histogram_h(labels, [x * y for x, y in zip(v1, v2)],
                                         colour=traffic_report.DARK_CYAN,
                                         unicode_graphics=True)
