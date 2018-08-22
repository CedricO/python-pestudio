import re

import pefile
from functools import reduce
from collections import Counter
import inspect

import string
import peutils
import entropy
import hashlib

class Pemanager(object):
    filename = ''
    def __init__(self, filename):
        self.filename = filename
        self.pe = pefile.PE(filename)

    def get_entropy(self):
        file_data = open(self.filename, "rb").read()
        return entropy.shannon_entropy(file_data)

    def get_md5(self):
        filehash = hashlib.md5()
        filehash.update(open(self.filename, 'rb').read())
        return filehash.hexdigest()

    def get_sha1(self):
        filehash = hashlib.sha1()
        filehash.update(open(self.filename, 'rb').read())
        return filehash.hexdigest()

    def get_signature(self):
        with open('userdb.txt', 'rt', encoding="ISO-8859-1") as f:
            sig_data = f.read()
        signatures = peutils.SignatureDatabase(data=sig_data)

        matches = signatures.match(self.pe, ep_only=True)
        print(matches)
        return matches[0]

    def get_sections(self):
        return self.pe.sections
       

    def get_file_type(self):
        file_type = self.pe.VS_FIXEDFILEINFO.FileType
        return {
            1: 'The file contains an application.',
            2: 'The file contains a DLL.',
            3: 'The file contains a device driver. dwFileSubtype contains a more specific description of the driver.',
            4: 'The file contains a font. dwFileSubtype contains a more specific description of the font file.',
            5: 'The file contains a virtual device.',
            7: 'The file contains a static-link library.',
            0: 'The file type is unknown to the system.'
        }[file_type]

    def get_imports(self):
        # TODO: Debug this function. Seems to have problems.
        res = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll)
            for imp in entry.imports:
                print(imp)
                res.append({'name': bytes(imp.name).decode("utf-8"), 'address': hex(imp.hint_name_table_rva),
                            'library': bytes(entry.dll).decode("utf-8")})

        return res

    def get_exports(self):
        try:
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)
        except AttributeError:
            print("No exports")

    def get_libraries(self):
        res = []
        num_imports = []
        j = 0
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            res.append(bytes(entry.dll).decode("utf-8"))
            num_imports.append(len(entry.imports))
        return  dict(zip(res, num_imports))

    def get_dos_headers(self):
        return self.pe.DOS_HEADER

    def get_optional_header(self):
        return self.pe.OPTIONAL_HEADER

    def get_file_headers(self):
        #for header in self.pe.DOS_HEADER
        return self.pe.FILE_HEADER

    def get_imphash(self):
        print("imphash" + self.pe.get_imphash())
        return hex(int(str(self.pe.get_imphash()), base=16))

    def get_directories(self):
        return self.pe.OPTIONAL_HEADER.DATA_DIRECTORY

    def get_warnings(self):
        warnings = []
        warnings.append(self.check_section_unaligned())
        warnings.append(self.check_section_oversized())
        warnings.append(self.check_communication_imports())
        warnings.append(self.check_dll_with_no_exports())
        warnings.append(self.check_checksum_is_zero())
        warnings.append(self.check_dll_with_no_exports())
        warnings.append(self.check_checksum_mismatch())
        warnings.append(self.check_corrupted_imports())
        warnings.append(self.check_image_size_incorrect())
        warnings.append(self.check_anti_debug_imports())
        warnings.append(self.check_com_service_imports())
        warnings.append(self.check_crypto_imports())
        warnings.append(self.check_elevating_privs_imports())
        warnings.append(self.check_empty_section_name())
        warnings.append(self.check_invalid_entry_point())
        warnings.append(self.check_keylogging_imports())
        warnings.append(self.check_nonstandard_section_name())
        warnings.append(self.check_overlapping_headers())
        warnings.append(self.check_process_manipulation())
        warnings.append(self.check_process_spawn())
        warnings.append(self.check_stealth_load())
        warnings.append(self.check_system_integrity_imports())
        warnings.append(self.check_system_probe_imports())
        warnings.append(self.check_system_state_imports())
        return warnings


    def get_file_info(self):
        return self.pe.FileInfo

    def get_subsystem_string(self):
        subsystem = str(self.get_optional_header().Subsystem)
        return {
            '0': 'UNKNOWN',
            '1': 'NATIVE',
            '2': 'WINDOWS_GUI',
            '3': 'WINDOWS_CUI',
            '5': 'OS2_CUI',
            '7': 'POSIX_CUI',
            '9': 'WINDOWS_CE_GUI',
            '10': 'EFI_APPLICATION',
            '11': 'EFI_BOOT_SERVICE_DRIVER',
            '12': 'EFI_RUNTIME_DRIVER',
            '13': 'EFI_ROM',
            '14': 'XBOX',
            '15': 'WINDOWS_BOOT_APPLICATION'
        }.get(subsystem, 'Unknown')

    def get_strings(self, filename, min=4):
        with open(filename, errors="ignore") as f:  # Python 3.x
            result = ""
            for c in f.read():
                if c in string.printable:
                    result += c
                    continue
                if len(result) >= min:
                        yield result
                result = ""
            if len(result) >= min:  # catch result at EOF
                yield result
        return result


    def print_info(self):
        return self.pe.print_info()

    def get_section_headers(self):
        return self.pe.__IMAGE_SECTION_HEADER_format__

    '''
    Code extracted form the workbench software.
    Visit http://workbench.readthedocs.io/en/latest/ for more information.
    
    '''

    def _search_within_pe_warnings(self, matches):
        """ Just encapsulating a search that takes place fairly often """
        pattern = '|'.join(re.escape(match) for match in matches)
        exp = re.compile(pattern)
        if any(exp.search(warning) for warning in self.pe.get_warnings()):
            return True

        return False

    def _search_for_import_symbols(self, matches):
        """ Just encapsulating a search that takes place fairly often """

        # Sanity check
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return []

        # Find symbols that match
        pattern = '|'.join(re.escape(match) for match in matches)
        exp = re.compile(pattern)
        symbol_list = []
        for module in self.pe.DIRECTORY_ENTRY_IMPORT:
            for symbol in module.imports:
                if (symbol.name):
                    symbol_list.append(bytes(symbol.name).decode("utf-8").lower())
        symbol_matches = []
        for symbol in symbol_list:
            if exp.search(symbol):
                symbol_matches.append(symbol)
        return symbol_matches

    def _search_for_export_symbols(self, matches):
        """ Just encapsulating a search that takes place fairly often """
        pattern = '|'.join(re.escape(match) for match in matches)
        exp = re.compile(pattern)
        symbol_list = []
        try:
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if symbol.name:
                    symbol_list.append(symbol.name.lower())
            symbol_matches = []
            for symbol in symbol_list:
                if exp.search(symbol):
                    symbol_matches.append(symbol)
            return symbol_matches
        except AttributeError:
            return []

    def _get_check_methods(self):
        results = []
        for key in dir(self):
            try:
                value = getattr(self, key)
            except AttributeError:
                continue
            if inspect.ismethod(value) and key.startswith('check'):
                results.append(value)
        return results

    def check_section_unaligned(self):
        """ Checking if any of the sections are unaligned  """
        file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        unaligned_sections = []
        for section in self.pe.sections:
            if section.PointerToRawData % file_alignment:
                unaligned_sections.append(section.Name)

        # If we had any unaligned sections, return them
        if unaligned_sections:
            return {'description': 'Unaligned section, tamper indication',
                    'severity': 3, 'category': 'MALFORMED', 'attributes': unaligned_sections}
        return None

    def check_section_oversized(self):
        """ Checking if any of the sections go past the total size of the image """
        total_image_size = self.pe.OPTIONAL_HEADER.SizeOfImage

        for section in self.pe.sections:
            if section.PointerToRawData + section.SizeOfRawData > total_image_size:
                return {'description': 'Oversized section, storing addition data within the PE',
                        'severity': 3, 'category': 'MALFORMED', 'attributes': section.Name}

        return None

    def check_dll_with_no_exports(self):
        """ Checking if the PE is a DLL with no exports"""
        if self.pe.is_dll() and not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return {'description':'DLL with NO export symbols', 'severity':3, 'category':'MALFORMED'}
        else:
            return None

    def check_communication_imports(self):
        """ Checking if the PE imports known communication methods"""
        imports = ['accept', 'bind', 'connect', 'connectnamedpipe', 'ftpputfile', 'getadaptersinfo',
                   'gethostbyname', 'gethostname', 'inet_addr', 'internetopen', 'internetopenurl',
                   'internetreadfile', 'internetwritefile', 'netshareenum', 'recv', 'send',
                   'urldownloadtofile', 'wsastartup']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description':'Imported symbols related to network communication', 'severity': 1,
                    'category':'COMMUNICATION', 'attributes':matching_imports}
        else:
            return None

    def check_corrupted_imports(self):
        """ Various ways the imports table might be corrupted. """
        pe_warning_matches = ['Error parsing the import directory at RVA:',
                              'Error parsing the import directory. Invalid Import data at RVA:',
                              'Error parsing the Delay import directory at RVA:',
                              'Error parsing the Delay import directory. Invalid import data at RVA:']

        # Search for any of the possible matches
        match_hits = self._search_within_pe_warnings(pe_warning_matches)
        if match_hits:
            return {'description': 'Corrupted import table', 'severity': 3,
                    'category': 'MALFORMED', 'attributes': match_hits}
        else:
            return None

    def check_checksum_is_zero(self):
        """ Checking for a checksum of zero """
        if self.pe.OPTIONAL_HEADER:
            if not self.pe.OPTIONAL_HEADER.CheckSum:
                return {'description': 'Checksum of Zero', 'severity': 1, 'category': 'MALFORMED'}
        return None

    def check_checksum_mismatch(self):
        """ Checking for a checksum that doesn't match the generated checksum """
        if self.pe.OPTIONAL_HEADER:
            if self.pe.OPTIONAL_HEADER.CheckSum != self.pe.generate_checksum():
                return {'description': 'Reported Checksum does not match actual checksum',
                        'severity': 2, 'category': 'MALFORMED'}
        return None

    def check_empty_section_name(self):
        """ Checking for an empty section name """
        for section in self.pe.sections:
            if not section.Name:
                return {'description': 'Section with no name, tamper indication',
                        'severity': 3, 'category': 'MALFORMED'}
        return None

    def check_nonstandard_section_name(self):
        """ Checking for an non-standard section name """
        std_sections = ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.idata',
                        '.pdata', '.debug', '.reloc', '.stab', '.stabstr', '.tls',
                        '.crt', '.gnu_deb', '.eh_fram', '.exptbl', '.rodata']
        for i in range(200):
            std_sections.append('/'+str(i))
        non_std_sections = []
        for section in self.pe.sections:
            name = convert_to_ascii_null_term(section.Name).lower()
            if (name not in std_sections):
                non_std_sections.append(name)
        if non_std_sections:
            return{'description': 'Section(s) with a non-standard name, tamper indication',
                   'severity': 3, 'category': 'MALFORMED', 'attributes': non_std_sections}

        return None

    def check_image_size_incorrect(self):
        """ Checking if the reported image size matches the actual image size """
        last_virtual_address = 0
        last_virtual_size = 0

        section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        total_image_size = self.pe.OPTIONAL_HEADER.SizeOfImage

        for section in self.pe.sections:
            if section.VirtualAddress > last_virtual_address:
                last_virtual_address = section.VirtualAddress
                last_virtual_size = section.Misc_VirtualSize

        # Just pad the size to be equal to the alignment and check for mismatch
        last_virtual_size += section_alignment - (last_virtual_size % section_alignment)
        if (last_virtual_address + last_virtual_size) != total_image_size:
            return {'description': 'Image size does not match reported size',
                    'severity': 3, 'category': 'MALFORMED'}

        return None

    def check_overlapping_headers(self):
        """ Checking if pefile module reported overlapping header """
        matches = ['Error parsing the resources directory, attempting to read entry name. Entry names overlap']

        # Search for any of the possible matches
        match_hits = self._search_within_pe_warnings(matches)
        if match_hits:
            return {'description': 'Overlapping sections', 'severity': 3, 'category': 'MALFORMED'}

    def check_elevating_privs_imports(self):
        """ Checking if the PE imports known methods associated with elevating or attaining new privileges"""
        imports = ['adjusttokenprivileges', 'certopensystemstore', 'deviceiocontrol', 'isntadmin',
                   'lsaenumeratelogonsessions', 'mmgetsystemroutineaddress', 'ntsetinformationprocess',
                   'samiconnect', 'samigetprivatedata', 'samqueryinformationuse']
        matching_imports = self._search_for_import_symbols(imports)
        if (matching_imports):
            return {'description': 'Imported symbols related to elevating or attaining new privileges',
                    'severity': 2, 'category': 'CREDENTIALS', 'attributes': matching_imports}
        else:
            return None

    def check_keylogging_imports(self):
        """ Checking if the PE imports known methods associated with elevating or attaining new privileges"""
        imports = ['attachthreadinput', 'bitblt', 'callnexthookex', 'getasynckeystate',
                   'getdc', 'savedc', 'getforgroundwindow', 'getkeystate', 'mapvirtualkey'
                   'registerhotkey', 'setwindowshookex']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to keylogging activities', 'severity': 2,
                    'category': 'KEYLOGGING', 'attributes': matching_imports}
        else:
            return None

    def check_system_state_imports(self):
        """ Checking if the PE imports known methods associated with changing system state"""
        imports = ['createfile', 'createfilemapping', 'readfile', 'openfile', 'deletefile',
                   'setfiletime', 'createmutex', 'openmutex', 'gettemppath', 'getwindowsdirectory',
                   'ntquerydirectoryfile', 'regopenkey', 'rtlcreateregistrykey', 'rtlwriteregistryvalue',
                   'wow64disablewow64fsredirection']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to changing system state', 'severity': 1,
                    'category': 'SYSTEM_STATE', 'attributes': matching_imports}
        else:
            return None

    def check_system_probe_imports(self):
        """ Checking if the PE imports known methods associated with probing the system"""
        imports = ['findfirstfile', 'findnextfile', 'findresource', 'getsystemdefaultlangid', 'getversionex']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to probing the system', 'severity': 2,
                    'category': 'SYSTEM_PROBE', 'attributes': matching_imports}
        else:
            return None

    def check_system_integrity_imports(self):
        """ Checking if the PE imports known methods associated with system security or integrity"""
        imports = ['enableexecuteprotectionsupport', 'mapviewoffile', 'sfcterminatewatcherthread']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to system security and integrity',
                    'severity': 3, 'category': 'SYSTEM_INTEGRITY', 'attributes': matching_imports}
        else:
            return None

    def check_crypto_imports(self):
        """ Checking if the PE imports known methods associated with encryption"""
        imports = ['crypt']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to encryption', 'severity': 3,
                    'category': 'ENCRYPTION', 'attributes': matching_imports}
        else:
            return None

    def check_anti_debug_imports(self):
        """ Checking if the PE imports known methods associated with anti-debug"""
        imports = ['checkremotedebbugerpresent', 'isdebuggerpresent', 'ntqueryinformationprocess',
                   'outputdebugstring', 'queryperformancecounter', 'gettickcount', 'findwindow']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to anti-debugging', 'severity': 3,
                    'category': 'ANTI_DEBUG', 'attributes': matching_imports}
        else:
            return None

    def check_com_service_imports(self):
        """ Checking if the PE imports known methods associated with COM or services"""
        imports = ['cocreateinstance', 'controlservice', 'createservice', 'dllcanunloadnow',
                   'dllgetclassobject', 'dllinstall', 'dllregisterserver', 'dllunregisterserver',
                   'oleinitialize', 'openscmanager', 'startservicectrldispatcher']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to COM or Services', 'severity': 3,
                    'category': 'COM_SERVICES', 'attributes': matching_imports}
        else:
            return None

    def check_process_manipulation(self):
        """ Checking if the PE imports known methods associated with process manipulation/injection"""
        imports = ['createremotethread', 'createtoolhelp32snapshot', 'enumprocesses',
                   'enumprocessmodules', 'getmodulefilename', 'getmodulehandle', 'getstartupinfo',
                   'getthreadcontext', 'iswow64process', 'module32first', 'module32next', 'openprocess',
                   'process32first', 'process32next', 'queueuserapc', 'readprocessmemory', 'resumethread',
                   'setthreadcontext', 'suspendthread', 'thread32first', 'thread32next',
                   'toolhelp32readprocessmemory', 'virtualallocex', 'virtualprotectex', 'writeprocessmemory']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to process manipulation/injection',
                    'severity': 3, 'category': 'PROCESS_MANIPULATION', 'attributes': matching_imports}
        else:
            return None

    def check_process_spawn(self):
        """ Checking if the PE imports known methods associated with spawning a new process"""
        imports = ['createprocess', 'netschedulejobadd', 'peeknamedpipe', 'shellexecute',
                   'system', 'winexec']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to spawning a new process', 'severity': 2,
                    'category': 'PROCESS_SPAWN', 'attributes': matching_imports}
        else:
            return None

    def check_stealth_load(self):
        """ Checking if the PE imports known methods associated with loading libraries, resources, etc in a sneaky way"""
        imports = ['getprocaddress', 'ldrloaddll', 'loadlibrary', 'loadresource']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to loading libraries, resources, in a sneaky way',
                    'severity': 2, 'category': 'STEALTH_LOAD', 'attributes': matching_imports}
        else:
            return None

    def check_invalid_entry_point(self):
        """ Checking the PE File warning for an invalide entry point """
        matches = ['Possibly corrupt file. AddressOfEntryPoint lies outside the file. AddressOfEntryPoint:',
                   'AddressOfEntryPoint lies outside the sections\' boundaries. AddressOfEntryPoint:']
        # Search for any of the possible matches
        match_hits = self._search_within_pe_warnings(matches)
        if match_hits:
            return {'description': 'Invalid Entry Point', 'severity': 3,
                    'category': 'OBFUSCATION', 'attributes': match_hits}
        else:
            return None


#Helper functions:
def convert_to_ascii_null_term(string):
    """ Convert string to null terminated ascii string """
    string = string.decode("ascii", 'ignore').split('\x00', 1)[0]
    return string