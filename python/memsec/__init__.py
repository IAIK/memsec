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
import subprocess
import timeit

def merge_dicts(*dict_args):
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def bdGenericName(module,genericName):
  cellName = 'memsec_0'
  if genericName in ['PCW_FPGA0_PERIPHERAL_FREQMHZ', 'PCW_FCLK0_PERIPHERAL_CLKSRC']:
    cellName = 'processing_system7_0'
  return '{}FLOW_VIVADO_BD_GENERIC_{}_AT_{}'.format(module,genericName,cellName)

def abbrevateSynthStrategy(fullname):
  return {
        'Vivado Synthesis Defaults' : None,
        'Flow_AlternateRoutability' : 'FAR',
        'Flow_AreaOptimized_medium' : 'FAOm',
        'Flow_AreaOptimized_high'   : 'FAOh',
        'Flow_PerfOptimized_high'   : 'FPOh',
        'Flow_PerfThresholdCarry'   : 'FPTC',
        'Flow_RuntimeOptimized'     : 'FRO'
    }.get(fullname, fullname)

def abbrevateImplStrategy(fullname):
  return {
        'Vivado Implementation Defaults' : None,
        'Flow_RunPostRoutePhysOpt'       : 'FRPRPO',
        'Performance_Explore'            : 'PE',
        'Performance_NetDelay_high'      : 'PNDh',
        'Performance_NetDelay_low'       : 'PNDl'
    }.get(fullname, fullname)

def binaryDirName(optionsDict):
  name = []
  if 'CRYPTO_CONFIG' in optionsDict.keys():
    name += ['CONFIG{}'.format(optionsDict['CRYPTO_CONFIG'])]
  if 'PCW_FPGA0_PERIPHERAL_FREQMHZ' in optionsDict.keys():
    name += ['{}MHZ'.format(optionsDict['PCW_FPGA0_PERIPHERAL_FREQMHZ'])]
  if 'TREE_ROOTS' in optionsDict.keys():
    name += ['R{}'.format(optionsDict['TREE_ROOTS'])]
  if 'TREE_ARITY' in optionsDict.keys():
    name += ['A{}'.format(optionsDict['TREE_ARITY'])]
  if 'BLOCKS_PER_SECTOR' in optionsDict.keys():
    name += ['BPS{}'.format(optionsDict['BLOCKS_PER_SECTOR'])]
  if 'DATA_BLOCK_SIZE' in optionsDict.keys():
    name += ['B{}'.format(optionsDict['DATA_BLOCK_SIZE'])]
  if 'FLOW_VIVADO_SYNTH_STRATEGY' in optionsDict.keys() and abbrevateSynthStrategy(optionsDict['FLOW_VIVADO_SYNTH_STRATEGY']):
    name += ['S{}'.format(abbrevateSynthStrategy(optionsDict['FLOW_VIVADO_SYNTH_STRATEGY']))]
  if 'FLOW_VIVADO_IMPL_STRATEGY' in optionsDict.keys() and abbrevateImplStrategy(optionsDict['FLOW_VIVADO_IMPL_STRATEGY']):
    name += ['I{}'.format(abbrevateImplStrategy(optionsDict['FLOW_VIVADO_IMPL_STRATEGY']))]
  if 'DATASTREAM_DATA_WIDTH' in optionsDict.keys():
    name += ['W{}'.format(optionsDict['DATASTREAM_DATA_WIDTH'])]
  if len(name) == 0:
    return None
  return "_"+"_".join(name)

def run(module,targets,binaryRootDir=None,envVars=[]):
  envVars += [ "FLOW_MODULE=\"{}\"".format(module) ]
  if binaryRootDir:
    envVars += [ "FLOW_BINARY_ROOT_DIR=\"{}\"".format(binaryRootDir) ]
  command = ' '.join(envVars) + ' ' + ' '.join(['make'] + targets)
  print("Running \"" + command + "\"...", flush=True)
  start = timeit.default_timer()
  returncode = subprocess.call(command, shell=True)
  end = timeit.default_timer()
  if returncode != 0:
    print("Running \"" + command + "\"... FAILED! (Return code = {}) {} s".format(returncode, end-start), flush=True)
  else:
    print("Running \"" + command + "\"... OK! {} s".format(end-start), flush=True)
  return  {'COMMAND': command, 'RETURN_CODE': returncode, 'EXECUTION_TIME': end-start, 'ERROR': True if returncode != 0 else False }

def configureDatastreamDataWidth(datastream_width):
  print("Configuring DATASTREAM_DATA_WIDTH={}.".format(datastream_width));
  with open('hdl/memsec_config.vhd', 'r') as input_file, open('hdl/memsec_config.vhd.tmp', 'w') as output_file:
    for line in input_file:
      if 'DATASTREAM_DATA_WIDTH' in line:
        output_file.write("  constant DATASTREAM_DATA_WIDTH : integer := {};\n".format(datastream_width));
      else:
        output_file.write(line);
  os.remove('hdl/memsec_config.vhd');
  os.rename('hdl/memsec_config.vhd.tmp', 'hdl/memsec_config.vhd');
  return

def buildBitStream(module,bdGenericsDict={},optionsDict={}):
  sumDict     = merge_dicts(bdGenericsDict, optionsDict)
  configureDatastreamDataWidth(optionsDict.pop('DATASTREAM_DATA_WIDTH',64))
  varStrings  = ["{}={}".format(bdGenericName(module,k),v) for k,v in bdGenericsDict.items()]
  varStrings += ["{}=\"{}\"".format(k,v) for k,v in optionsDict.items()]
  res = run(module,['implcb', 'clean'], binaryDirName(sumDict),varStrings)
  return [merge_dicts(res, { 'OPTIONS': sumDict })]

def runTest(module,genericsDict={},optionsDict={}):
  sumDict     = merge_dicts(genericsDict, optionsDict)
  configureDatastreamDataWidth(optionsDict.pop('DATASTREAM_DATA_WIDTH',64))
  varStrings  = ["{}GENERIC_{}=\"{}\"".format(module,k,v) for k,v in genericsDict.items()]
  varStrings += ["{}=\"{}\"".format(k,v) for k,v in optionsDict.items()]
  res = run(module,['hdlsb', 'clean'], binaryDirName(sumDict),varStrings)
  return [merge_dicts(res, { 'OPTIONS': sumDict })]

def printSummary(resList):
  print("")
  print("------------------------------------------------------------------------------")
  print("Summary:")
  print("------------------------------------------------------------------------------")
  failed = 0
  for res in resList:
    if res['ERROR']:
      failed = failed + 1
      print("ERROR! {:8.3f}s (Return code = {}) {} {}".format(res['EXECUTION_TIME'], res['RETURN_CODE'], binaryDirName(res['OPTIONS']), res['OPTIONS']))
    else:
      print("OK!    {:8.3f}s (Return code = {}) {} {}".format(res['EXECUTION_TIME'], res['RETURN_CODE'], binaryDirName(res['OPTIONS']), res['OPTIONS']))
  print("")
  if len(resList) > 0:
    print("{} out of {} failed. ({:.1f}%)".format(failed, len(resList), 100*failed/len(resList)))
  print("------------------------------------------------------------------------------")
  return failed
