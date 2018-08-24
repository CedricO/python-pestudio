# Python PEStudio

This project aims at analyzing Portable Executable (PE) binaries.
It is inspired by PEstudio only available on Windows versions.  


## Requirements

Python 3 is required. You can install the Python requirements  using
    `pip3 install -r requirements.txt`

## Functionalities
- Generate XML file reports: Full analysis report
- Print to console only parts of the report (File header, Optional header, Section header, librairies and imports)
- Print a scan from VirusTotal

## Usage
 - Specify your VirusTotal API key: `python3 pypestudio.py -k APIKEY`
 - Full XML report (PE info + VirusTotal) `python3 pypestudio.py -f testfile.exe`
 - Partial XML report (PE info only): `python3 pypestudio.py -x testfile.exe`
 - Print file headers `python3 pypestudio.py -fh testfile.exe`
 - Print optional headers `python3 pypestudio.py -oh testfile.exe`
 - Print section headers `python3 pypestudio.py -sh testfile.exe`
 - Print libraries `python3 pypestudio.py -l testfile.exe`
 - Print imports `python3 pypestudio.py -im testfile.exe`
 - Print all information `python3 pypestudio.py -i testfile.exe`
 - Print a scan from VirusTotal with the default key `python3 pypestudio.py -s testfile.exe`
 - Print a scan from VirusTotal with a temporary key `python3 pypestudio.py -k 'key' -s testfile.exe`

The default key can be changed inside the file `virt.py`. 
The key we use by default is limited to 4 requests per minute.
More information at https://www.virustotal.com/en/documentation/public-api/


 
## TODO
- The calculation of the file entropy in the 'overview' section is incorrect.
- The DOS Stub section of the report is empty and has no command line

## Credits 
Some inspiration came from the workbench software (for the indicators section of the code).
Visit http://workbench.readthedocs.io/en/latest/ for more information.
    

## Contributors
Thibaud Griet (Thibaud.Griet@eurecom.fr)

Cedric Osornio (osornio@eurecom.fr)
