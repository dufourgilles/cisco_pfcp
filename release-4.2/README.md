# Cisco PFCP Wireshark Dissector

A modified version of PFCP dissector for Wireshark supporting Cisco private IE and
compressed format.

## Installation

Win64 Wireshark 4.2 plugin version 0.0.15 [download](http://www.gdnet.be/Wireshark/win64_cisco_pfcp_4_2_v0_0_15.dll)

MAC OS Wireshark 4.2 plugin version 0.0.15 [download](http://www.gdnet.be/Wireshark/macos_cisco_pfcp_4_2_v_0_0_15.so)

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
