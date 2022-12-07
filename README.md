# Semm: A Polymorphic Malware Analysis Tool
## Introduction
With Antivirus software struggling to detect Polymorphic malware, this type of malware is finding its way into machines much easier than malicious software seen in the past. This has created the need for a new method of detection, which has come to a forefront with the tool: Semm

Semm analyzes a file by breaking it into its instruction code and creating permutations of this code, emulating the process a polymorphic engine takes when it changes the code in a malware sample. The primary goal of Semm is to enable detection of polymorphic malware through tools like YARA and AV (Antivirus Software), however it can also be used to optimize machine code and help obfuscate code as well.

## Installation
To Install Semm using Python, run the following commands:
```
git clone https://github.com/pjv4yj/Semm.git
cd Semm
pip3 install .
```
These commands will install the semm_ops package allowing use of the Assembler, Disassembler, and Transforms

## Example Use and Output
This is the initial input hex bytecode from the sample file:
```
68110440e8110400c3c3fd92d9b84d818420114898f848df4008024364a9211888ee487492088a188150c27be866e30249761
```
This python script disassembles this hex from the sample EXE file, transforms the registers, and returns the bytecode for all of these permutations.
```
from semm_ops.disassembly import Disassembler
from semm_ops.transform import Transform

d = Disassembler() # instantiate Disassembler Object
operation_arr = d.get_instruction_list('../sample_files/sample1.exe', num_bytes=100) # operation list from first instruction for 100 bytes

t = Transform(operation_arr[0:20]) # Initiate Transform Object
byte_codes = t.transform_registers() # Transform registers

for code in byte_codes: # Print out each byte code permutation
    print(code)
```

And the output looks as follows:
```
68110440e8110400c3c3fd92d9b84d818420114898f848df4008024364a9211888ee487492088a188150c27be866e30249761
68110440e8110400c3c3fd91d9b84d818420a48910f848df4008024364a9111908ee487491090a188150c27be866e30248f61
68110440e8110400c3c3fd93d9b84d8184201a48910f848df4008024364a9311908ee487493090a188150c27be866e30249f61
68110440e8110400c3c3fd91d9b84d818420b48918f848df4008024364a9111988ee487491098a188150c27be866e30248f61
68110440e8110400c3c3fd93d9b84d8184201a48910f848df4008024364a9311908ee487493090a188150c27be866e30249f61
68110440e8110400c3c3fd92d9b84d8184201348918f848df4008024364a9211988ee487492098a188150c27be866e30249761
68110440e8110400c3c3fd87d3d9bb4d818420104b93f848cf4008024364a87d311838ee487487d3083a188150c27be866e303c9761
68110440e8110400c3c3fd91d9b84d818420b48918f848df4008024364a9111988ee487491098a188150c27be866e30248f61
68110440e8110400c3c3fd93d9bb4d81842014b9bf848df4008024364a93118b8ee48749308ba188150c27be866e303c8761
68110440e8110400c3c3fd87d9d9b94d8184201a49911f848cf4008024364a87d911918ee487487d9091a188150c27be866e302c9f61
68110440e8110400c3c3fd92d9b84d818420114898f848df4008024364a9211888ee487492088a188150c27be866e30249761
68110440e8110400c3c3fd93d9bb4d81842014b9bf848df4008024364a93118b8ee48749308ba188150c27be866e303c8761
68110440e8110400c3c3fd91d9b84d818420b48918f848df4008024364a9111988ee487491098a188150c27be866e30248f61
68110440e8110400c3c3fd87d1d9b94d818420104991f848cf4008024364a87d111818ee487487d1081a188150c27be866e302c9761
68110440e8110400c3c3fd92d9b84d818420114898f848df4008024364a9211888ee487492088a188150c27be866e30249761
68110440e8110400c3c3fd91d9b94d818420249911f848df4008024364a9111918ee487491091a188150c27be866e302c8761
68110440e8110400c3c3fd91d9b84d818420b48918f848df4008024364a9111988ee487491098a188150c27be866e30248f61
68110440e8110400c3c3fd87d9d9b94d8184201a49911f848cf4008024364a87d911918ee487487d9091a188150c27be866e302c9f61
68110440e8110400c3c3fd93d9bb4d81842014b9bf848df4008024364a93118b8ee48749308ba188150c27be866e303c8761
68110440e8110400c3c3fd92d9b84d818420114898f848df4008024364a9211888ee487492088a188150c27be866e30249761
68110440e8110400c3c3fd87cad9ba4d81842084a92f848cf4008024364a87ca11828ee487487ca082a188150c27be866e30348f61
68110440e8110400c3c3fd91d9b84d818420a48910f848df4008024364a9111908ee487491090a188150c27be866e30248f61
68110440e8110400c3c3fd92d9ba4d81842034a91af848df4008024364a92119a8ee48749209aa188150c27be866e30348761
68110440e8110400c3c3fd92d9b84d818420114898f848df4008024364a9211888ee487492088a188150c27be866e30249761
```


## Current Capabilities
- Disassembly of PE Executable into an "Operation Array", or a list of all of the assembly operations for a specified number of bytes
- Transforming these operations to include every x86 register combination possible. This transform will generate every possible combination of x86 registers in the instruction code
- Reassembling this operation array into hex bytecode to be used in Antivirus software or relevant YARA rules

## Future Capabilities
- Transforming x86 instructions by replacing them with functionally equiavalent but different commands
- Swapping the order of instructions in the assembly while maintaining the same functional output




