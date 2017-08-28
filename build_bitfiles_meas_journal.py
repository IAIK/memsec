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

module ='full_memenc'
res = []

# package the IP core
run('memsec',['info', 'vivado_package', 'distclean'])

globalBdGenerics = {'PCW_FPGA0_PERIPHERAL_FREQMHZ': 50}

globalOptionDict = {'FLOW_VIVADO_IMPL_STRATEGY': 'Flow_RunPostRoutePhysOpt'}

## MEAS
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 9,'TREE_ROOTS': 1024,'DATA_BLOCK_SIZE': 64})
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 2}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 64}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 4}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 64}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 8}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 64}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 2}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 128}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 4}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 128}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 8}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 128}))

## MEAS ECB
localBdGenerics = merge_dicts(globalBdGenerics, {'CRYPTO_CONFIG': 10,'TREE_ROOTS': 1024,'DATA_BLOCK_SIZE': 64})
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 2}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 64}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 4}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 64}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 8}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 64}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 2}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 128}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 4}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 128}))
#res += buildBitStream(module,merge_dicts(localBdGenerics, {'TREE_ARITY': 8}),merge_dicts(globalOptionDict,{'DATASTREAM_DATA_WIDTH': 128}))

# build MEAS (ECB) with different optimizer settings
synthOptionDictList = [{'FLOW_VIVADO_SYNTH_STRATEGY': 'Flow_AlternateRoutability'},
                       {'FLOW_VIVADO_SYNTH_STRATEGY': 'Flow_PerfOptimized_high'},
                       {'FLOW_VIVADO_SYNTH_STRATEGY': 'Flow_PerfThresholdCarry'}]

implOptionDictList = [{'FLOW_VIVADO_IMPL_STRATEGY': 'Flow_RunPostRoutePhysOpt'}]

localBdGenerics = merge_dicts(globalBdGenerics, {'TREE_ARITY': 4,'TREE_ROOTS': 1024,'DATA_BLOCK_SIZE': 64})
for synthOptionsDict in synthOptionDictList:
  for implOptionsDict in implOptionDictList:
    optionsDict = merge_dicts(implOptionsDict,synthOptionsDict,{'DATASTREAM_DATA_WIDTH': 128})
    res += buildBitStream(module,merge_dicts(localBdGenerics, {'CRYPTO_CONFIG': 9}),optionsDict)
    res += buildBitStream(module,merge_dicts(localBdGenerics, {'CRYPTO_CONFIG': 10}),optionsDict)

sys.exit(printSummary(res))
