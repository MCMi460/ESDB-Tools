#@author PlatinumMaster
#@category GUI
#@language Python

from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from java.io import File
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException
# import yaml

def get_file_from_user():
    return askFile("Save", "Save")

segments = {}
symbols = {}

file_path = get_file_from_user()
if file_path:
    symbol_table = currentProgram.getSymbolTable()
    iterator = symbol_table.getAllSymbols(True)
    while iterator.hasNext():
        s = iterator.next()
        symbol_name = s.getName()
        symbol_segment = s.getAddress().getAddressSpace().getName().strip("::")
        address_fixup = s.getAddress().getOffset()

        block = currentProgram.getMemory().getBlock(s.getAddress())
        if block is None:
            continue 

        # If the symbol segment is not in the segments, add the info
        if symbol_segment not in segments.keys():
            fixed_segment_name = symbol_segment
            # TODO: Figure out how to automatically determine BSS/DATA
            segment_type = 'EXECUTABLE'
            if "overlay_" in symbol_segment:
                segment_type = 'OVERLAY'
                fixed_segment_name = symbol_segment.split("_")[-1]
            if symbol_segment == "ram":
                fixed_segment_name = "ARM9"

            segments.update({ 
                symbol_segment : {
                    'Name' : fixed_segment_name,
                    'Type' : segment_type,
                }
            })
            
        ctx = currentProgram.getProgramContext()
        addr = s.getAddress()

        tmode_reg = ctx.getRegister("TMode") 
        val = ctx.getValue(tmode_reg, addr, False)
        is_thumb = (val == 1) if val is not None else False
        address_fixup += 1 if is_thumb else 0

        # Ignore thunked functions
        functionManager = currentProgram.getFunctionManager()
        function = functionManager.getFunctionAt(addr)
        if symbol_name.endswith('+1') or function and function.isThunk():
            continue

        # Add symbol (or merge if a +1 is there)
        fixed_name = symbol_name.strip('+1') 
        symbols.update({ 
            fixed_name : {
                'Name' : fixed_name,
                'Segment' : symbol_segment,
                'Address' : address_fixup,
            }
        })

    with open(file_path.getAbsolutePath(), 'w') as ESDB:
        segment_keys = list(segments.keys())
        ESDB.write("Segments:\n")
        for segment_name, segment_meta in segments.items():
            ESDB.write("  - ID: 0x{:X}\n".format(segment_keys.index(segment_name)))
            ESDB.write("    Name: {}\n".format(segment_meta["Name"]))
            ESDB.write("    Type: {}\n".format(segment_meta["Type"]))
        ESDB.write("\n")

        ESDB.write("Symbols:\n")
        for sym, meta in symbols.items():
            ESDB.write("  - Name: {}\n".format(sym))
            ESDB.write("    Segment: 0x{:X}\n".format(segment_keys.index(meta["Segment"])))
            ESDB.write("    Address: 0x{:X}\n".format(meta["Address"]))
        