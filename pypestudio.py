from virt import VirusTotal
import json
import sys
import argparse
from bs4 import BeautifulSoup
from bs4 import Comment
import pemanager

from functools import reduce
import datetime
import re
import os
import numpy as np

import bcolors


def generate_report(file_name):
    virustotal = VirusTotal()

    #file_sent = virustotal.send_files([file_name])
    file_report = virustotal.retrieve_files_reports([file_name])
    md5 = file_report['md5']
    sha1 = file_report['sha1']
    sha256 = file_report['sha256']
    link = file_report['permalink']
    print("md5 "+md5)
    print("sha1 "+sha1)
    print("sha256 "+sha256)
    print("file "+link)
    print(json.dumps(file_report))
    for scan in file_report.values():
        print(scan)


def main(filename, *args):
    print("Performing the scan with", filename)
    generate_report(filename)

    for arg in args:
        k = arg.split("=")[0]
        v = arg.split("=")[1]

        print ("Keyword argument: %s = %s" % (k, v))


def generate_xml(pe, filename, file_report):
    soup = BeautifulSoup(features='lxml')
    soup.append(soup.new_tag("image"))
    image = soup.image
    image["name"] = filename
    # Overview of the file
    image.append(soup.new_tag("overview"))
    overview = soup.overview
    file_desc_tag = soup.new_tag("file-description")

    try:

        file_info = pe.get_file_info()[0].StringTable[0].entries
        file_desc_tag.string = bytes(file_info[b'FileDescription']).decode('utf8')

    except (AttributeError, UnboundLocalError, KeyError):

        file_desc_tag.string = str("Unknown")
    finally:

        overview.append(file_desc_tag)

    file_version_tag = soup.new_tag("file-version")

    try:

        file_version_tag.string = bytes(file_info[b'FileVersion']).decode('utf8')
    except (AttributeError, UnboundLocalError, KeyError):
        file_version_tag.string = str("Unknown")
    finally:
        overview.append(file_version_tag)

    created_tag = soup.new_tag("created")
    created_tag.string = "00:00:0000 - 00:00:00"
    overview.append(created_tag)
    cpu_tag = soup.new_tag("cpu")
    if(pe.get_optional_header().Magic == 0x10b):
        cpu_tag.string = "32"
    elif(pe.get_optional_header().Magic == 0x20b):
        cpu_tag.string = "64"
    else:
        cpu_tag = "Unknown"
    overview.append(cpu_tag)
    size_tag = soup.new_tag("size")
    size_tag.string = str(os.stat(filename).st_size)
    overview.append(size_tag)
    type_tag = soup.new_tag("type")
    type_tag.string = pe.get_file_type()
    overview.append(type_tag)
    subsystem_tag = soup.new_tag("subsystem")
    subsystem_tag.string = pe.get_subsystem_string()
    overview.append(subsystem_tag)

    signature_tag = soup.new_tag("signature")

    try:

        signature = pe.get_signature()
        signature_tag.string = str(signature)

    except TypeError:
        signature_tag.string = str("No known signature found. userdb.txt should be updated")
    finally:
        overview.append(signature_tag)


    entropy_tag = soup.new_tag("entropy")
    entropy_tag.string = str(pe.get_entropy())
    overview.append(entropy_tag)
    md5_tag = soup.new_tag("md5")
    md5_tag.string = str(pe.get_md5())
    overview.append(md5_tag)
    sha1_tag = soup.new_tag("sha1")
    sha1_tag.string = str(pe.get_sha1())
    overview.append(sha1_tag)
    imphash_tag = soup.new_tag("imphash")
    imphash_tag.string = pe.get_imphash()
    overview.append(imphash_tag)

    # Indicators of the file
    image.append(soup.new_tag("indicators"))
    indicators = soup.indicators
    warnings = pe.get_warnings()
    indicators['count'] = len(warnings) - warnings.count(None)

    for warning in warnings:
        if warning:
            indicator_tag = soup.new_tag("indicator", severity=warning['severity'], category=warning['category'].lower())
            indicator_tag.string = warning['description']
            indicators.append(indicator_tag)

    # Virus Total analysis
    virustotal_tag = soup.new_tag("virustotal")
    if file_report:
            positives_tag = soup.new_tag("positives")
            positives_tag.string = str(file_report['positives'])
            virustotal_tag.append(positives_tag)
            total_scans_tag = soup.new_tag("total_scans")
            total_scans_tag.string = str(file_report['total'])
            virustotal_tag.append(total_scans_tag)
            permalink_tag = soup.new_tag("permalink")
            permalink_tag.string = str(file_report['permalink'])
            virustotal_tag.append(permalink_tag)
            scan_date_tag = soup.new_tag("scan_date")
            scan_date_tag.string = str(file_report['scan_date'])
            av_tag = soup.new_tag("antivirus")
            for key, values in file_report['scans'].items():
                av_tag_detail = soup.new_tag("antivirus-details")
                av_name_tag = soup.new_tag("antivirus_name")
                av_name_tag.string = str(key)
                for tag, value in values.items():
                    detected_tag = soup.new_tag(tag)
                    detected_tag.string = str(value)
                    av_tag_detail.append(detected_tag)
                    av_tag.append(av_tag_detail)
                av_tag_detail.append(av_name_tag)
            virustotal_tag.append(av_tag)
            image.append(virustotal_tag)

    # DOS Stub
    image.append(soup.new_tag("dos_stub"))
    dos_stub = image.dos_stub
    dos_stub_size_tag = soup.new_tag("size")
    dos_stub_size_tag.string = "64"
    dos_stub.append(dos_stub_size_tag)
    dos_stub_md5_tag = soup.new_tag("md5")
    dos_stub_md5_tag.string = "md5"
    dos_stub.append(dos_stub_md5_tag)
    dos_stub_entropy_tag = soup.new_tag("entropy")
    dos_stub_entropy_tag.string = "0.0"
    dos_stub.append(dos_stub_entropy_tag)

    # File Header
    image.append(soup.new_tag("file_header"))
    file_header = image.file_header
    file_header_machine_tag = soup.new_tag("machine")
    file_header_machine_tag.string = hex(pe.get_file_headers().Machine)
    file_header.append(file_header_machine_tag)
    file_header_sections_tag = soup.new_tag("sections")
    file_header_sections_tag.string = hex(pe.get_file_headers().NumberOfSections)
    file_header.append(file_header_sections_tag)
    file_header_stamp_tag = soup.new_tag("compiler-stamps")
    file_header_stamp_tag.string = datetime.datetime.fromtimestamp(pe.get_file_headers().TimeDateStamp)\
        .strftime('%a %b %d %H:%M:%S %Y')
    file_header.append(file_header_stamp_tag)
    file_header_pointer_tag = soup.new_tag("pointer-symbol-table") 
    file_header_pointer_tag.string = hex(pe.get_file_headers().PointerToSymbolTable)
    file_header.append(file_header_pointer_tag)
    file_header_symbol_tag = soup.new_tag("Number-of-symbol")
    file_header_symbol_tag.string = hex(pe.get_file_headers().NumberOfSymbols)
    file_header.append(file_header_symbol_tag)
    file_header_optionHeader_tag = soup.new_tag("Size-of-optional-header")
    file_header_optionHeader_tag.string =  hex(pe.get_file_headers().SizeOfOptionalHeader)
    file_header.append(file_header_optionHeader_tag)
    file_header_relocstrip_tag = soup.new_tag("Relocation-stripped")
    file_header_relocstrip_tag.string = str((pe.get_file_headers().Characteristics & 0x001))
    file_header.append(file_header_relocstrip_tag)
    file_header_executable_tag = soup.new_tag("Is-executable")
    file_header_executable_tag.string = str((pe.get_file_headers().Characteristics & 0x002) >> 1)
    file_header.append(file_header_executable_tag)
    file_header_largeaddress_tag = soup.new_tag("Large-address-aware")
    file_header_largeaddress_tag.string = str((pe.get_file_headers().Characteristics & 0x0020) >> 5)
    file_header.append(file_header_largeaddress_tag)
    file_header_cpu32_tag = soup.new_tag("Cpu-32")
    file_header_cpu32_tag.string = str((pe.get_file_headers().Characteristics & 0x0100) >> 8)
    file_header.append(file_header_cpu32_tag)
    file_header_uniprocessor_tag = soup.new_tag("Uniprocessor")
    file_header_uniprocessor_tag.string = str((pe.get_file_headers().Characteristics & 0x4000) >> 18)
    file_header.append(file_header_uniprocessor_tag)
    file_header_system_tag = soup.new_tag("System")
    file_header_system_tag.string = str((pe.get_file_headers().Characteristics & 0x1000) >> 12)
    file_header.append(file_header_system_tag)
    file_header_imagedll_tag = soup.new_tag("Image-dll")
    file_header_imagedll_tag.string = str((pe.get_file_headers().Characteristics & 0x2000) >> 13)
    file_header.append(file_header_imagedll_tag)
    file_header_debugstripped_tag = soup.new_tag("Debug-stripped")
    file_header_debugstripped_tag.string = str((pe.get_file_headers().Characteristics & 0x0200) >> 9)
    file_header.append(file_header_debugstripped_tag)
    file_header_removablerunFromSwap_tag = soup.new_tag("Removable-run-from-swap")
    file_header_removablerunFromSwap_tag.string = str((pe.get_file_headers().Characteristics & 0x0400) >> 10)
    file_header.append(file_header_removablerunFromSwap_tag)
    file_header_largeaddress_tag = soup.new_tag("Network-run-from-swap")
    file_header_largeaddress_tag.string = str((pe.get_file_headers().Characteristics & 0x0800) >> 11)
    file_header.append(file_header_largeaddress_tag)

    

    # optional-header
    optional_header = soup.new_tag("optional-header")
    optional_header_magic_tag = soup.new_tag("Magic")
    optional_header_magic_tag.string = hex(pe.get_optional_header().Magic)
    optional_header.append(optional_header_magic_tag)
    optional_header_linker_tag = soup.new_tag("Linker-version")
    optional_header_linker_tag.string = str(pe.get_optional_header().MinorLinkerVersion)+str(".")+str(pe.get_optional_header().MajorLinkerVersion)
    optional_header.append(optional_header_linker_tag)
    optional_header_code_tag = soup.new_tag("Size-of-code")
    optional_header_code_tag.string = hex(pe.get_optional_header().SizeOfCode)
    optional_header.append(optional_header_code_tag)
    optional_header_initializeddata_tag = soup.new_tag("Size-of-initialized-data")
    optional_header_initializeddata_tag.string = hex(pe.get_optional_header().SizeOfInitializedData)
    optional_header.append(optional_header_initializeddata_tag)
    optional_header_uninitializeddata_tag = soup.new_tag("Size-of-uninitialized-data")
    optional_header_uninitializeddata_tag.string = hex(pe.get_optional_header().SizeOfUninitializedData)
    optional_header.append(optional_header_uninitializeddata_tag)
    optional_header_entry_tag = soup.new_tag("address-of-entry-point")
    optional_header_entry_tag.string = hex(pe.get_optional_header().AddressOfEntryPoint)
    optional_header.append(optional_header_entry_tag)
    optional_header_basecode_tag = soup.new_tag("Base-of-code")
    optional_header_basecode_tag.string = hex(pe.get_optional_header().BaseOfCode)
    optional_header.append(optional_header_basecode_tag)
    optional_header_basedata_tag = soup.new_tag("Base-of-data")
    optional_header_basedata_tag.string =hex(pe.get_optional_header().BaseOfData)
    optional_header.append(optional_header_basedata_tag)
    optional_header_imagebase_tag = soup.new_tag("Image-base")
    optional_header_imagebase_tag.string = hex(pe.get_optional_header().ImageBase)
    optional_header.append(optional_header_imagebase_tag)
    optional_header_sectionalignment_tag = soup.new_tag("Section-alignment")
    optional_header_sectionalignment_tag.string = hex(pe.get_optional_header().SectionAlignment) 
    optional_header.append(optional_header_sectionalignment_tag)
    optional_header_filealignment_tag = soup.new_tag("File-alignment")
    optional_header_filealignment_tag.string = hex(pe.get_optional_header().FileAlignment) 
    optional_header.append(optional_header_filealignment_tag)
    optional_header_osversion_tag = soup.new_tag("os-version")
    optional_header_osversion_tag.string = str(pe.get_optional_header().MajorOperatingSystemVersion)+str(".")+str(pe.get_optional_header().MinorOperatingSystemVersion)
    optional_header.append(optional_header_osversion_tag)
    optional_header_imageversion_tag = soup.new_tag("Image_version")
    optional_header_imageversion_tag.string = str(pe.get_optional_header().MajorImageVersion)+str(".")+str(pe.get_optional_header().MinorImageVersion)
    optional_header.append(optional_header_imageversion_tag)
    optional_header_subsystemversion_tag = soup.new_tag("Subsystem-version")
    optional_header_subsystemversion_tag.string = str(pe.get_optional_header().MajorSubsystemVersion)+str(".")+str(pe.get_optional_header().MinorSubsystemVersion)
    optional_header.append(optional_header_subsystemversion_tag)
    optional_header_win32_tag =soup.new_tag("Win32VersionValue")
    optional_header_win32_tag.string = hex(pe.get_optional_header().Reserved1)
    optional_header.append(optional_header_win32_tag)
    optional_header_sizeimage_tag = soup.new_tag("Size-of-image")
    optional_header_sizeimage_tag.string = hex(pe.get_optional_header().SizeOfImage)
    optional_header.append(optional_header_sizeimage_tag)
    optional_header_sizeheader_tag = soup.new_tag("Size-of-headers")
    optional_header_sizeheader_tag.string = hex(pe.get_optional_header().SizeOfHeaders)
    optional_header.append(optional_header_sizeheader_tag)
    optional_header_checksum_tag = soup.new_tag("Checksum")
    optional_header_checksum_tag.string = hex(pe.get_optional_header().CheckSum)
    optional_header.append(optional_header_checksum_tag)
    optional_header_subsystem_tag = soup.new_tag("Subsystem")
    optional_header_subsystem_tag.string = hex(pe.get_optional_header().Subsystem)
    optional_header.append(optional_header_subsystem_tag)
    optional_header_stackreserve_tag = soup.new_tag("Size-of-stack-reserve")
    optional_header_stackreserve_tag.string = hex(pe.get_optional_header().SizeOfStackReserve)
    optional_header.append(optional_header_stackreserve_tag)
    optional_header_stackcommit_tag = soup.new_tag("Size-of-stack-commit")
    optional_header_stackcommit_tag.string = hex(pe.get_optional_header().SizeOfStackCommit)
    optional_header.append(optional_header_stackcommit_tag)
    optional_header_heapreserve_tag = soup.new_tag("Size-of-heap-reserve")
    optional_header_heapreserve_tag.string = hex(pe.get_optional_header().SizeOfHeapReserve)
    optional_header.append(optional_header_heapreserve_tag)
    optional_header_heapcommit_tag = soup.new_tag("Size-of-heap-commit")
    optional_header_heapcommit_tag.string = hex(pe.get_optional_header().SizeOfHeapCommit)
    optional_header.append(optional_header_heapcommit_tag)
    optional_header_loaderflags_tag = soup.new_tag("Loader_flags")
    optional_header_loaderflags_tag.string = hex(pe.get_optional_header().LoaderFlags)
    optional_header.append(optional_header_loaderflags_tag)
    optional_header_rva_tag = soup.new_tag("NumberOfRvaAndSizes")
    optional_header_rva_tag.string = hex(pe.get_optional_header().NumberOfRvaAndSizes)
    optional_header.append(optional_header_rva_tag)
    
    image.append(optional_header)

    # Directories:
    directories_tag = soup.new_tag("directories")
    for directory in pe.get_directories():
        directory_tag = soup.new_tag("directory")
        directory_tag['name'] = str(directory.name).replace('IMAGE_DIRECTORY_ENTRY_', '').lower()
        directory_tag['size'] = directory.Size
        directory_tag['address'] = hex(directory.VirtualAddress)
        directories_tag.append(directory_tag)
    image.append(directories_tag)

    dos_header = soup.new_tag("dos-header")
    dos_header_emagic_tag = soup.new_tag("e-magic")
    dos_header_emagic_tag.string = hex(pe.get_dos_headers().e_magic)
    dos_header.append(dos_header_emagic_tag)
    
    image.append(dos_header)
    
    #Section Header
    sections = pe.get_sections()
    header_section = soup.new_tag("Sections")
    header_section['count'] = len(sections)
    for sec in sections:
        header_section_tag = soup.new_tag("Section")
        header_section_tag_name = soup.new_tag("Name")
        if u'\x00' in bytes(sec.Name).decode("utf8"):
            header_section_tag_name.string = bytes(sec.Name).decode("utf-8").split(u'\x00')[0]
        else:
            header_section_tag_name.string = bytes(sec.Name).decode("utf-8")
        header_section_tag.append(header_section_tag_name)
        header_section_tag_virtualsize = soup.new_tag("Virtual-size")
        header_section_tag_virtualsize.string = str(sec.Misc_VirtualSize)
        header_section_tag.append(header_section_tag_virtualsize)
        header_section_tag_vitualaddress = soup.new_tag("Virtual-address")
        header_section_tag_vitualaddress.string = hex(sec.VirtualAddress)
        header_section_tag.append(header_section_tag_vitualaddress)
        header_section_tag_rawdata = soup.new_tag("Size-of-raw-data")
        header_section_tag_rawdata.string = hex(sec.SizeOfRawData)
        header_section_tag.append(header_section_tag_rawdata)
        header_section_tag_pointerrawdata = soup.new_tag("Pointer-to-raw-data")
        header_section_tag_pointerrawdata.string = hex(sec.PointerToRawData)
        header_section_tag.append(header_section_tag_pointerrawdata)
        header_section_tag_pointerrelocation = soup.new_tag("Pointer-to-relocations")
        header_section_tag_pointerrelocation.string = hex(sec.PointerToRelocations)
        header_section_tag.append(header_section_tag_pointerrelocation)
        header_section_tag_pointerlinenumber = soup.new_tag("Pointer-to-line-numbers")
        header_section_tag_pointerlinenumber.string = hex(sec.PointerToLinenumbers) 
        header_section_tag.append(header_section_tag_pointerlinenumber)
        header_section_tag_numberrelocation = soup.new_tag("Number-of-relocations")
        header_section_tag_numberrelocation.string = hex(sec.NumberOfRelocations)
        header_section_tag.append(header_section_tag_numberrelocation)
        header_section_tag_numberline = soup.new_tag("Number-of-line-numbers")
        header_section_tag_numberline.string = hex(sec.NumberOfLinenumbers)
        header_section_tag.append(header_section_tag_numberline)
        header_section_tag_md5 = soup.new_tag("MD5")
        header_section_tag_md5.string = str(sec.get_hash_md5())
        header_section_tag.append(header_section_tag_md5)
        header_section_tag_entropy = soup.new_tag("Entropy")
        header_section_tag_entropy.string = str(sec.get_entropy())
        header_section_tag.append(header_section_tag_entropy)
        header_section.append(header_section_tag)
        header_section_tag_inidata = soup.new_tag("Initialized-data")
        header_section_tag_inidata.string = str((sec.Characteristics & 0x00000040) >> 6)
        header_section_tag.append(header_section_tag_inidata)
        header_section_tag_uinidata = soup.new_tag("Uninitialized-data")
        header_section_tag_uinidata.string = str((sec.Characteristics & 0x00000080) >> 7)
        header_section_tag.append(header_section_tag_uinidata)
        header_section_tag_discardable = soup.new_tag("Discardable")
        header_section_tag_discardable.string = str((sec.Characteristics & 0x02000000) >> 25)
        header_section_tag.append(header_section_tag_discardable)
        header_section_tag_cached = soup.new_tag("Cannot-be-cached")
        header_section_tag_cached.string = str((sec.Characteristics & 0x04000000) >> 26)
        header_section_tag.append(header_section_tag_cached)
        header_section_tag_paged = soup.new_tag("Cannot-be-paged")
        header_section_tag_paged.string = str((sec.Characteristics & 0x08000000) >> 27)
        header_section_tag.append(header_section_tag_paged)
        header_section_tag_executable = soup.new_tag("Executable")
        header_section_tag_executable.string = str((sec.Characteristics & 0x20000000) >> 29)
        header_section_tag.append(header_section_tag_executable)
        header_section_tag_readable = soup.new_tag("Readable")
        header_section_tag_readable.string = str((sec.Characteristics & 0x40000000) >> 30)
        header_section_tag.append(header_section_tag_readable)
        header_section_tag_writable = soup.new_tag("Writable")
        header_section_tag_writable.string = str((sec.Characteristics & 0x80000000) >> 31)
        header_section_tag.append(header_section_tag_writable)
    image.append(header_section)
        
        
    
    # Libraries
    counter_librairies = pe.get_libraries()
    image.append(soup.new_tag("libraries"))
    libraries = image.libraries
    libraries['count'] = len(counter_librairies)
    for key, value in counter_librairies.items():
        library_tag = soup.new_tag('library', names=key, imports=value)
        libraries.append(library_tag)


    # Imports:
    file_imports = pe.get_imports()
    image.append(soup.new_tag("imports"))
    imports = image.imports
    imports['count'] = len(file_imports)
    for file_import in file_imports:
        import_tag = soup.new_tag('import', names=file_import['name'].lower(), address=file_import['address'].upper(),
                                  library=file_import['library'])
        imports.append(import_tag)


    # Strings
    strings = pe.get_strings(filename)
    strings_tag = soup.new_tag("strings")
    string_ascii_tag = soup.new_tag("ascii")
    for element in strings:
        string_tag = soup.new_tag("string")
        string_tag.append(soup.new_string(xml_printable(element)))
        string_ascii_tag.append(string_tag)
    strings_tag.append(string_ascii_tag)
    image.append(strings_tag)

    print(soup.prettify(formatter="xml"))
    save_xml_to_file(soup)

def print_file_header(pe):

    print(pe.get_file_headers())

def print_optional_header(pe):

    print(pe.get_optional_header())

def print_section_header(pe):

    for sec in pe.get_sections():

        print(sec)
        print("\n")

def print_library(pe):
    print("Librairies : \n")
    for sec in pe.get_libraries():

        print(sec)

def print_import(pe):

    for sec in pe.get_imports():
        print(sec)
        print("\n")

def save_xml_to_file(soup, filename='report.xml'):
    with open(filename, 'w') as f:
        for line in soup:
            f.write(str(line).replace("_", "-"))
    f.close()


def xml_printable(s):
    return re.sub(pattern=(u'[\u0000-\u0008\u000B\u000C\u000E-\u001F'
                           u'\u007F-\u009F\uD800-\uDFFF\uFDD0-\uFDEF\uFFFE\uFFFF]'),
                  repl=u'\N{REPLACEMENT CHARACTER}',
                  string=s)

if __name__ == "__main__":

    parser  = argparse.ArgumentParser(description="pes_studio tool")
    parser.add_argument("-k", "--key", help="Specify the VirusTotal API key", metavar="PATH")
    parser.add_argument("-s", "--scan", help = "scan the file with VirusTotal", metavar="PATH")
    parser.add_argument("-i", "--allPEinfo", help="Print all info about PE info", metavar ="PATH")
    parser.add_argument("-x","--XMLReport", help="Generate an XML report", metavar = "PATH")
    parser.add_argument("-fh", "--Fileheader", help="Print the file headers", metavar="PATH")
    parser.add_argument("-oh", "--Optionalheader", help="Print the optional headers", metavar="PATH")
    parser.add_argument("-sh", "--Sectionheader", help="Print the section headers", metavar="PATH")
    parser.add_argument("-l", "--library", help="Print the libraries", metavar="PATH")
    parser.add_argument("-im", "--imports", help="Print the imports", metavar="PATH")

    args = parser.parse_args()

    file_report = None

    if len(sys.argv) < 2:
        raise SyntaxError("Insufficient arguments.")

    if(args.scan):
        if args.key:
            virustotal = VirusTotal(apikey=str(args.key))
        else:
            virustotal = VirusTotal()

            file_hash = virustotal.send_files([args.scan])
            file_report = virustotal.retrieve_files_reports([args.scan])
            for data in file_report :
                if(data ==  "scans"):
                    for scanner in file_report[data]:
                        if(file_report[data][scanner]['detected'] == True):
                            print(scanner ," : ", bcolors.FAIL , file_report[data][scanner], bcolors.ENDC )
                        else:
                            print(scanner ," : ",file_report[data][scanner])
                    
                else:
                    print(data ," = ",file_report[data])
                    print("\n")

    if(args.allPEinfo):
        pe = pemanager.Pemanager(args.allPEinfo)
        pe.print_info()

    if(args.XMLReport):
        pe = pemanager.Pemanager(args.XMLReport)

        generate_xml(pe, args.XMLReport, file_report)

    if(args.Fileheader):
        pe = pemanager.Pemanager(args.Fileheader)
        print_file_header(pe)

    if(args.Optionalheader):
        pe = pemanager.Pemanager(args.Optionalheader)
        print_optional_header(pe)

    if(args.Sectionheader):
        pe = pemanager.Pemanager(args.Sectionheader)
        print_section_header(pe)

    if(args.library):
        pe = pemanager.Pemanager(args.library)
        print_library(pe)

    if(args.imports):
        pe = pemanager.Pemanager(args.imports)
        print_import(pe)

