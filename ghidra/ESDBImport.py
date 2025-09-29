#@author PlatinumMaster
#@category GUI
#@language Python

from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from java.io import File
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException
import yaml

def get_file_from_user():
    chooser = JFileChooser()
    esdb_filter = FileNameExtensionFilter("ESDB (*.yml)", ["yml"])
    chooser.setFileFilter(esdb_filter)
    chooser.setDialogTitle('Choose your ESDB')
    result = chooser.showOpenDialog(None)
    
    if result == JFileChooser.APPROVE_OPTION:
        selected_file = chooser.getSelectedFile()
        print(f'ESDB path: {selected_file.getAbsolutePath()}')
        return selected_file.getAbsolutePath()
    else:
        return None

file_path = get_file_from_user()
if file_path:
    # Load the ESDB.
    with open(file_path, 'r') as f:
        esdb = yaml.load(f, Loader=yaml.SafeLoader)

    # Load the segment map, then build an segment -> symbol meta map.
    esdb_segment_map = {}
    for segment in esdb['Segments']:
        esdb_segment_map |= {
            segment['ID'] : {
                'Name' : segment['Name'],
                'Type' : segment['Type'],
            }
        }

    esdb_symbol_map = {}
    for symbol_meta in esdb['Symbols']:
        # If not already defined, define it.
        segment_meta = esdb_segment_map[symbol_meta['Segment']]
        if (symbol_name := segment_meta['Name']) not in esdb_symbol_map:
            esdb_symbol_map.update({
                symbol_name : {}
            })

        # Address -> symbol mapping (for reverse lookup).
        esdb_symbol_map[symbol_name] |= {
            symbol_meta['Address'] : symbol_meta['Name'],
        }

    def get_symbol_by_address(address):
        if address in esdb_symbol_map.keys():
            return esdb_symbol_map[address]
        return None

    memory = currentProgram().getMemory()
    ghidra_segments = memory.getBlocks()
    ghidra_segment_map = {}
    for segment in ghidra_segments:
        ghidra_segment_map |= {
            segment.getName() : {
                'Start' : segment.getStart(),
                'End' : segment.getEnd(),
            }
        }
    
    symbol_table = currentProgram().getSymbolTable()
    for segment_name, symbols in esdb_symbol_map.items():
        ghidra_segment_name_candidates = []
        ghidra_segment_name = ''

        if segment_name.startswith('ARM9'):
            ghidra_segment_name_candidates.append('ARM9')
        elif segment_name.startswith('OVL'):
            tokens = segment_name.split('_')
            overlay_tag, overlay_number = tokens[:2]
            ghidra_segment_name_candidates.append(f'overlay_{overlay_number}')
            ghidra_segment_name_candidates.append(f'overlay_d_{overlay_number}')

        for name in ghidra_segment_name_candidates:
            if name in ghidra_segment_map:
                ghidra_segment_name = name
                print(f'Found segment {ghidra_segment_name}!')
                break
        
        if ghidra_segment_name == '':
            print(f'Skipping segment {segment_name}')
            continue

        segment_meta = ghidra_segment_map[ghidra_segment_name] 
        
        print(f'Renaming symbols in {ghidra_segment_name}...')

        for address, label in symbols.items():
            corrected_address = address - (address & 1)
            ghidra_symbol = symbol_table.getPrimarySymbol(toAddr(corrected_address))
            if ghidra_symbol:
                old_name = ghidra_symbol.getName()
                try:
                    new_label = label
                    ghidra_symbol_address = ghidra_symbol.getAddress().getOffset()
                    print(f"Ghidra sym addr: {hex(ghidra_symbol_address)}")
                    if (ghidra_symbol_address) != corrected_address:
                        delta = corrected_address - ghidra_symbol_address
                        new_label = f'_{new_label}_{hex(delta)}'
                    ghidra_symbol.setName(new_label, SourceType.USER_DEFINED)
                    print(f"Renamed {old_name} to {new_label}")
                except:
                    pass

        