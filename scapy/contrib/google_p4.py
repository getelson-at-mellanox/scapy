# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Next Header  |   Hrd Ext Len | R | Crypt Off |S|D|Version|V|1| DW0
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Security Params Index (SPI)                  | DW1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               | DW2
# +                   Initialization Vector (IV)                  +
# |                                                               | DW3
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               | DW4
# +              Virtualization Cookie (VC) [Optional]            +
# |                                                               | DW5
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# from scapy.contrib.google_p4 import GP4

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitField, BitEnumField,
    IntField, LongField,
    ConditionalField
)
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6


class GP4(Packet):
    name = "GP4"
    fields_desc = [BitEnumField("next_protocol",
                                4, 8,
                                {4: "IP",
                                 6: "IP6"}),
                   BitField("ext_len", 0, 8),
                   BitField("reserved", 0, 16),
                   IntField("SPI", 0),
                   ConditionalField(LongField("iv", 0),
                                    lambda pkt: pkt.ext_len in [1, 2]),
                   ConditionalField(LongField("vc", 0),
                                    lambda pkt: pkt.ext_len == 2)
                   ]

    def mysummary(self):
        return self.sprintf("Google P4 %GP4.next_protocol% %GP4.ext_len%")


bind_layers(UDP, GP4, dport=0x3103)
bind_layers(GP4, IP, next_protocol=4)
bind_layers(GP4, IPv6, next_protocol=6)
