#!/usr/bin/env python3

# MEMSEC - Framework for building transparent memory encryption and authentication solutions.
# Copyright (C) 2017-2018 Graz University of Technology, IAIK <mario.werner@iaik.tugraz.at>
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
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "python"))
from memsec import *

module ='memsec'
res = []

# determine the default backend which will be used for the tests
infoOutput = subprocess.check_output(["make", "info"]).decode()
backend = re.search('FLOW_BACKEND:\s+(\w+)', infoOutput).group(1)

# Test the cryptographic primitives alone
for r in [5,6,7]:
  res += runTest(module, {'ROUNDS': r}, {'FLOW_SIM_TOP': 'tb_qarma'})
res += runTest(module, {}, {'FLOW_SIM_TOP': 'tb_prince'})
res += runTest(module, {}, {'FLOW_SIM_TOP': 'tb_aes'})
res[-1]['ERROR'] = not res[-1]['ERROR'] # the AES test is currently expected to fail
for r in [1,2,3,6]:
  res += runTest(module, {'UNROLED_ROUNDS': r}, {'FLOW_SIM_TOP': 'tb_ascon'})

# Test the different pipelines
# ghdl is currently not supported
if backend != "ghdl":
  generics = {'SIMULATION_ITERATIONS': 50}

  # PLAIN
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 0,'BLOCKS_PER_SECTOR': 1}))

  # ASCON
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 1,'DATA_BLOCK_SIZE': 32}))

  # ASCON TREE
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 2,'TREE_ROOTS': 1,'TREE_ARITY': 8,'DATA_BLOCK_SIZE': 64}))

  # Prince ECB
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 3,'BLOCKS_PER_SECTOR': 4}))

  # AES ECB
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 4,'BLOCKS_PER_SECTOR': 2}))

  # Prince CBC
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 5,'BLOCKS_PER_SECTOR': 4}))

  # AES CBC
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 6,'BLOCKS_PER_SECTOR': 2}))

  # Prince XTS
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 7,'BLOCKS_PER_SECTOR': 4}))

  # AES XTS
  res += runTest(module,merge_dicts(generics, {'CRYPTO_CONFIG': 8,'BLOCKS_PER_SECTOR': 2}))

  # MEAS
  localGenerics = merge_dicts(generics, {'CRYPTO_CONFIG': 9,'TREE_ROOTS': 1,'TREE_ARITY': 4,'DATA_BLOCK_SIZE': 64})
  res += runTest(module,localGenerics)
  res += runTest(module,localGenerics,{'DATASTREAM_DATA_WIDTH': 128})

  # MEAS ECB
  localGenerics = merge_dicts(generics, {'CRYPTO_CONFIG': 10,'TREE_ROOTS': 1,'TREE_ARITY': 4,'DATA_BLOCK_SIZE': 64})
  res += runTest(module,localGenerics)
  res += runTest(module,localGenerics,{'DATASTREAM_DATA_WIDTH': 128})

sys.exit(printSummary(res))
