#!/usr/bin/env python3

# MEMSEC - Framework for building transparent memory encryption and authentication solutions.
# Copyright (C) 2017 Graz University of Technology, IAIK <mario.werner@iaik.tugraz.at>
#
# This file is part of MEMSEC.
#
# MEMSEC is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MEMSEC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MEMSEC.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "python"))
from memsec import *

module = 'full_memenc'
res = []

# package the IP core
run('memsec',['info', 'vivado_package', 'distclean'])

# PCW_FPGA0_PERIPHERAL_FREQMHZ, PCW_FCLK0_PERIPHERAL_CLKSRC, ...
globalBdGenerics = {'PCW_FPGA0_PERIPHERAL_FREQMHZ': 100}

globalOptionDictList = [ {},
                         {'FLOW_VIVADO_IMPL_STRATEGY': 'Performance_NetDelay_high'},
                         {'FLOW_VIVADO_IMPL_STRATEGY': 'Performance_NetDelay_low'},
                         {'FLOW_VIVADO_IMPL_STRATEGY': 'Flow_RunPostRoutePhysOpt'} ]

# PLAIN
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 0,'BLOCKS_PER_SECTOR': 4})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# ASCON
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 1, 'DATA_BLOCK_SIZE': 32})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# ASCON TREE
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 2,'TREE_ROOTS': 1024, 'TREE_ARITY': 8,'DATA_BLOCK_SIZE': 64})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# Prince ECB
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 3,'BLOCKS_PER_SECTOR': 4})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# AES ECB
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 4,'BLOCKS_PER_SECTOR': 2})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# Prince CBC
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 5,'BLOCKS_PER_SECTOR': 4})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# AES CBC
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 6,'BLOCKS_PER_SECTOR': 2})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# Prince XTS
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 7,'BLOCKS_PER_SECTOR': 4})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

# AES XTS
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 8,'BLOCKS_PER_SECTOR': 2})
for optionsDict in globalOptionDictList:
  res += buildBitStream(module,localBdGenerics,optionsDict)

sys.exit(printSummary(res))
