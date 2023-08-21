# Cisco PFCP Wireshark Dissector

A modified version of PFCP dissector for Wireshark supporting Cisco private IE and
compressed format.

## Installation

MAC OS Wireshark 3.1 plugin [download](http://www.gdnet.be/Wireshark/macos_3_1_cisco_pfcp.so)

MAC OS Wireshark 3.5 plugin version 0.0.7 [download](http://www.gdnet.be/Wireshark/macos_3_5_cisco_pfcp.so)

MAC OS Wireshark 3.6 plugin version 0.0.11 [download](http://www.gdnet.be/Wireshark/macos_3_6_cisco_pfcp.so)

Win64 Wireshark 3.6 plugin version 0.0.11 [download](http://www.gdnet.be/Wireshark/cisco_pfcp_3_6.dll)

MAC OS Wireshark 3.6 plugin version 0.0.12 [download](http://www.gdnet.be/Wireshark/macos_3_6_cisco_pfcp.so)

Win64 Wireshark 3.6 plugin version 0.0.12 [download](http://www.gdnet.be/Wireshark/cisco_pfcp_3_6.dll)

MAC OS Wireshark 4.0 plugin version 0.0.14 [download](http://www.gdnet.be/Wireshark/macos_4_0_cisco_pfcp.so)

MAC OS Intel Wireshark 4.0 plugin version 0.0.12a [download](http://www.gdnet.be/Wireshark/mac_cisco_pfcp_0.0.12a_intel.so)

MAC OS ARM Wireshark 4.0 plugin version 0.0.12a [download](http://www.gdnet.be/Wireshark/mac_cisco_pfcp_0.0.12a_arm.so)

Win64 Wireshark 4.0 plugin version 0.0.14 [download](http://www.gdnet.be/Wireshark/win64_cisco_pfcp_0.0.14.dll)

Win64 Wireshark 4.0 plugin version 0.0.13 [download](http://www.gdnet.be/Wireshark/win64_cisco_pfcp_0.0.13.dll)

Win64 Wireshark 4.0 plugin version 0.0.12a [download](http://www.gdnet.be/Wireshark/win64_cisco_pfcp_0.0.12.dll)

### Compiled plugins (*.dll or *.so)
    Compiled plugins are stored in subfolders of the plugin folders, with the subfolder name being the Wireshark minor version number (X.Y).
    There is another hierarchical level for each Wireshark plugin type (libwireshark, libwiretap and codecs).
    
    Current version of wireshark is 3.x, hence create directories as below where needed:
    
      * Windows:   
        * Personal: "%APPDATA%\Wireshark\plugins\3.x\epan\"   
        * Global:   "WIRESHARK\plugins\3.x\epan\"
        
      * Unix-like systems:  
        * Personal: "~/.local/lib/wireshark/plugins/3.x/epan/"
        
      * macOS:
        //you might need to install `libgcrypt`library
        * %APPDIR%/Contents/PlugIns/wireshark/3-x/epan/
        * INSTALLDIR/lib/wireshark/plugins/3-x/epan/
