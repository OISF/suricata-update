# Copyright (C) 2026 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from __future__ import print_function

import unittest

from suricata.update.commands import updatesources


class TestCompareSources(unittest.TestCase):

    def test_index_without_sources_key_does_not_crash(self):
        # A hand-edited index file may not have a "sources" key. Comparing
        # it must not raise TypeError.
        updatesources.compare_sources(
            {"other": 1}, {"sources": {"a": {"url": "x"}}})
        updatesources.compare_sources(
            {"sources": {"a": {"url": "x"}}}, {"other": 1})
        updatesources.compare_sources({"other": 1}, {"other": 2})
        updatesources.compare_sources({"other": 1}, None)
