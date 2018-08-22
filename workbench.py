'''
This python class codifies a bunch of rules around suspicious static
features in a PE File. The rules don't indicate malicious behavior
they simply flag things that may be used by a malicious binary.
Many of the indicators used were inspired by the material in the
'Practical Malware Analysis' book by Sikorski and Honig,
ISBN-13: 978-1593272906 (available on Amazon :)

Description:

    PE_WARNINGS          = PE module warnings verbatim
    MALFORMED            = the PE file is malformed
    COMMUNICATION        = network activities
    CREDENTIALS          = activities associated with elevating or attaining new privileges
    KEYLOGGING           = activities associated with keylogging
    SYSTEM_STATE         = file system or registry activities
    SYSTEM_PROBE         = getting information from the local system (file system, OS config)
    SYSTEM_INTEGRITY     = compromises the security state of the local system
    PROCESS_MANIPULATION = indicators associated with process manipulation/injection
    PROCESS_SPAWN        = indicators associated with creating a new process
    STEALTH_LOAD         = indicators associated with loading libraries, resources, etc in a sneaky way
    ENCRYPTION           = any indicators related to encryption
    COM_SERVICES         = COM functionality or running as a service
    ANTI_DEBUG           = anti-debugging indicators
'''

import re
import inspect
import pefile


class PEIndicators(object):
    ''' Create instance of Indicators class. This class uses the
        static features from the pefile module to look for weird stuff.

        Note: All methods that start with 'check' will be automatically
        included as part of the checks that happen when 'execute' is called.
    '''
    dependencies = ['sample']

    def __init__(self):
        ''' Init method of the Indicators class. '''
        self.pefile_handle = None

    def execute(self):
        ''' Execute the PEIndicators worker '''

        # Analyze the output of pefile for any anomalous conditions.
        # Have the PE File module process the file

        try:
            self.pefile_handle = pefile.PE('testfile.exe', fast_load=False)
        except (AttributeError, pefile.PEFormatError) as error:
            return {'error': str(error), 'indicator_list': [{'Error': 'PE module failed!'}]}

        indicators = []
        indicators += [{'description': warn, 'severity': 2, 'category': 'PE_WARN'}
                       for warn in self.pefile_handle.get_warnings()]

        # Automatically invoke any method of this class that starts with 'check'
        check_methods = self._get_check_methods()
        for check_method in check_methods:
            hit_data = check_method()
            if hit_data:
                indicators.append(hit_data)

        return {'indicator_list': indicators}

    #
    # Check methods
    #
    def check_corrupted_imports(self):
        ''' Various ways the imports table might be corrupted. '''
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
        ''' Checking for a checksum of zero '''
        if self.pefile_handle.OPTIONAL_HEADER:
            if not self.pefile_handle.OPTIONAL_HEADER.CheckSum:
                return {'description': 'Checksum of Zero', 'severity': 1, 'category': 'MALFORMED'}
        return None

    def check_checksum_mismatch(self):
        ''' Checking for a checksum that doesn't match the generated checksum '''
        if self.pefile_handle.OPTIONAL_HEADER:
            if self.pefile_handle.OPTIONAL_HEADER.CheckSum != self.pefile_handle.generate_checksum():
                return {'description': 'Reported Checksum does not match actual checksum',
                        'severity': 2, 'category': 'MALFORMED'}
        return None

    def check_empty_section_name(self):
        ''' Checking for an empty section name '''
        for section in self.pefile_handle.sections:
            if not section.Name:
                return {'description': 'Section with no name, tamper indication',
                        'severity': 3, 'category': 'MALFORMED'}
        return None

    def check_nonstandard_section_name(self):
        ''' Checking for an non-standard section name '''
        std_sections = ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.idata',
                        '.pdata', '.debug', '.reloc', '.stab', '.stabstr', '.tls',
                        '.crt', '.gnu_deb', '.eh_fram', '.exptbl', '.rodata']
        for i in range(200):
            std_sections.append('/'+str(i))
        non_std_sections = []
        for section in self.pefile_handle.sections:
            name = convert_to_ascii_null_term(section.Name).lower()
            if (name not in std_sections):
                non_std_sections.append(name)
        if non_std_sections:
            return{'description': 'Section(s) with a non-standard name, tamper indication',
                   'severity': 3, 'category': 'MALFORMED', 'attributes': non_std_sections}

        return None

    def check_image_size_incorrect(self):
        ''' Checking if the reported image size matches the actual image size '''
        last_virtual_address = 0
        last_virtual_size = 0

        section_alignment = self.pefile_handle.OPTIONAL_HEADER.SectionAlignment
        total_image_size = self.pefile_handle.OPTIONAL_HEADER.SizeOfImage

        for section in self.pefile_handle.sections:
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
        ''' Checking if pefile module reported overlapping header '''
        matches = ['Error parsing the resources directory, attempting to read entry name. Entry names overlap']

        # Search for any of the possible matches
        match_hits = self._search_within_pe_warnings(matches)
        if match_hits:
            return {'description': 'Overlapping sections', 'severity': 3, 'category': 'MALFORMED'}

    def check_section_unaligned(self):
        ''' Checking if any of the sections are unaligned '''
        pe = pefile.PE('testfile.exe')
        file_alignment = pe.OPTIONAL_HEADER.FileAlignment
        unaligned_sections = []
        for section in pe.sections:
            if section.PointerToRawData % file_alignment:
                unaligned_sections.append(section.Name)

        # If we had any unaligned sections, return them
        if unaligned_sections:
            return {'description': 'Unaligned section, tamper indication',
                    'severity': 3, 'category': 'MALFORMED', 'attributes': unaligned_sections}
        return None

    def check_section_oversized(self):
        ''' Checking if any of the sections go past the total size of the image '''
        total_image_size = self.pefile_handle.OPTIONAL_HEADER.SizeOfImage

        for section in self.pefile_handle.sections:
            if section.PointerToRawData + section.SizeOfRawData > total_image_size:
                return {'description': 'Oversized section, storing addition data within the PE',
                        'severity': 3, 'category': 'MALFORMED', 'attributes': section.Name}

        return None

    def check_dll_with_no_exports(self):
        ''' Checking if the PE is a DLL with no exports'''
        if self.pefile_handle.is_dll() and not hasattr(self.pefile_handle,'DIRECTORY_ENTRY_EXPORT'):
            return {'description':'DLL with NO export symbols', 'severity':3, 'category':'MALFORMED'}
        else:
            return None

    def check_communication_imports(self):
        ''' Checking if the PE imports known communication methods'''
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

    def check_elevating_privs_imports(self):
        ''' Checking if the PE imports known methods associated with elevating or attaining new privileges'''
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
        ''' Checking if the PE imports known methods associated with elevating or attaining new privileges'''
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
        ''' Checking if the PE imports known methods associated with changing system state'''
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
        ''' Checking if the PE imports known methods associated with probing the system'''
        imports = ['findfirstfile', 'findnextfile', 'findresource', 'getsystemdefaultlangid', 'getversionex']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to probing the system', 'severity': 2,
                    'category': 'SYSTEM_PROBE', 'attributes': matching_imports}
        else:
            return None

    def check_system_integrity_imports(self):
        ''' Checking if the PE imports known methods associated with system security or integrity'''
        imports = ['enableexecuteprotectionsupport', 'mapviewoffile', 'sfcterminatewatcherthread']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to system security and integrity',
                    'severity': 3, 'category': 'SYSTEM_INTEGRITY', 'attributes': matching_imports}
        else:
            return None

    def check_crypto_imports(self):
        ''' Checking if the PE imports known methods associated with encryption'''
        imports = ['crypt']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to encryption', 'severity': 3,
                    'category': 'ENCRYPTION', 'attributes': matching_imports}
        else:
            return None

    def check_anti_debug_imports(self):
        ''' Checking if the PE imports known methods associated with anti-debug'''
        imports = ['checkremotedebbugerpresent', 'isdebuggerpresent', 'ntqueryinformationprocess',
                   'outputdebugstring', 'queryperformancecounter', 'gettickcount', 'findwindow']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to anti-debugging', 'severity': 3,
                    'category': 'ANTI_DEBUG', 'attributes': matching_imports}
        else:
            return None

    def check_com_service_imports(self):
        ''' Checking if the PE imports known methods associated with COM or services'''
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
        ''' Checking if the PE imports known methods associated with process manipulation/injection'''
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
        ''' Checking if the PE imports known methods associated with spawning a new process'''
        imports = ['createprocess', 'netschedulejobadd', 'peeknamedpipe', 'shellexecute',
                   'system', 'winexec']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to spawning a new process', 'severity': 2,
                    'category': 'PROCESS_SPAWN', 'attributes': matching_imports}
        else:
            return None

    def check_stealth_load(self):
        ''' Checking if the PE imports known methods associated with loading libraries, resources, etc in a sneaky way'''
        imports = ['getprocaddress', 'ldrloaddll', 'loadlibrary', 'loadresource']
        matching_imports = self._search_for_import_symbols(imports)
        if matching_imports:
            return {'description': 'Imported symbols related to loading libraries, resources, in a sneaky way',
                    'severity': 2, 'category': 'STEALTH_LOAD', 'attributes': matching_imports}
        else:
            return None

    def check_invalid_entry_point(self):
        ''' Checking the PE File warning for an invalide entry point '''
        matches = ['Possibly corrupt file. AddressOfEntryPoint lies outside the file. AddressOfEntryPoint:',
                   'AddressOfEntryPoint lies outside the sections\' boundaries. AddressOfEntryPoint:']
        # Search for any of the possible matches
        match_hits = self._search_within_pe_warnings(matches)
        if match_hits:
            return {'description': 'Invalid Entry Point', 'severity': 3,
                    'category': 'OBFUSCATION', 'attributes': match_hits}
        else:
            return None

    def check_exports(self):
        ''' This is just a stub function right now, might be useful later '''
        exports = ['evil']
        self._search_for_export_symbols(exports)

    #
    # Helper methods
    #
    def _search_within_pe_warnings(self, matches):
        ''' Just encapsulating a search that takes place fairly often '''
        pattern = '|'.join(re.escape(match) for match in matches)
        exp = re.compile(pattern)
        if any(exp.search(warning) for warning in self.pefile_handle.get_warnings()):
            return True

        return False

    def _search_for_import_symbols(self, matches):
        ''' Just encapsulating a search that takes place fairly often '''

        # Sanity check
        if not hasattr(self.pefile_handle, 'DIRECTORY_ENTRY_IMPORT'):
            return []

        # Find symbols that match
        pattern = '|'.join(re.escape(match) for match in matches)
        exp = re.compile(pattern)
        symbol_list = []
        for module in self.pefile_handle.DIRECTORY_ENTRY_IMPORT:
            for symbol in module.imports:
                if (symbol.name):
                    symbol_list.append(symbol.name.lower())
        symbol_matches = []
        for symbol in symbol_list:
            if exp.search(symbol):
                symbol_matches.append(symbol)
        return symbol_matches

    def _search_for_export_symbols(self, matches):
        ''' Just encapsulating a search that takes place fairly often '''
        pattern = '|'.join(re.escape(match) for match in matches)
        exp = re.compile(pattern)
        symbol_list = []
        try:
            for symbol in self.pefile_handle.DIRECTORY_ENTRY_EXPORT.symbols:
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


# Helper functions
def convert_to_ascii_null_term(string):
    ''' Convert string to null terminated ascii string '''
    string = string.split('\x00', 1)[0]
    return string.decode('ascii', 'ignore')


# Unit test: Create the class, the proper input and run the execute() method for a test
def test():
    ''' pe_indicators.py: Unit test'''
    import pprint

    # This worker test requires a local server running
    import zerorpc
    workbench = zerorpc.Client(timeout=300, heartbeat=60)
    workbench.connect("tcp://127.0.0.1:4242")

    # Generate the input data for this worker
    import os
    data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             '../data/pe/bad/033d91aae8ad29ed9fbb858179271232')
    md5_bad = workbench.store_sample(open(data_path, 'rb').read(), 'bad_pe', 'exe')
    data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             '../data/pe/good/4be7ec02133544cde7a580875e130208')
    md5_good = workbench.store_sample(open(data_path, 'rb').read(), 'good_pe', 'exe')

    # Execute the worker (unit test)
    worker = PEIndicators()
    output = worker.execute(workbench.get_sample(md5_bad))
    print('\n<<< Unit Test 1 >>>')
    pprint.pprint(output)
    output = worker.execute(workbench.get_sample(md5_good))
    print('\n<<< Unit Test 2 >>>')
    pprint.pprint(output)

    # Execute the worker (server test)
    output = workbench.work_request('pe_indicators', md5_bad)
    print('\n<<< Server Test >>>')
    pprint.pprint(output)

if __name__ == "__main__":
    test()
