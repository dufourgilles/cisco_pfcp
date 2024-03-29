# Cisco PFCP Wireshark Dissector

A modified version of PFCP dissector for Wireshark supporting Cisco private IE and
compressed format.

## Installation


MAC OS Wireshark 4.0 plugin version 0.0.15 [download](http://www.gdnet.be/Wireshark/macos_4_0_cisco_pfcp.so)

Win64 Wireshark 4.0 plugin version 0.0.13 [download](http://www.gdnet.be/Wireshark/win64_cisco_pfcp_0.0.13.dll)

Win64 Wireshark 4.0 plugin version 0.0.14 [download](http://www.gdnet.be/Wireshark/win64_cisco_pfcp_0.0.14.dll)

Win64 Wireshark 4.0 plugin version 0.0.15 [download](http://www.gdnet.be/Wireshark/win64_cisco_pfcp_0.0.15.dll)

### Compiled plugins (*.dll or *.so)
    Compiled plugins are stored in subfolders of the plugin folders, with the subfolder name being the Wireshark minor version number (X.Y).
    There is another hierarchical level for each Wireshark plugin type (libwireshark, libwiretap and codecs).
    
    Current version of wireshark is 4.x, hence create directories as below where needed:
    
      * Windows:   
        * Personal: "%APPDATA%\Wireshark\plugins\4.x\epan\"   
        * Global:   "WIRESHARK\plugins\4.x\epan\"
        
      * Unix-like systems:  
        * Personal: "~/.local/lib/wireshark/plugins/4.x/epan/"
        
      * macOS:
        //you might need to install `libgcrypt`library
        * %APPDIR%/Contents/PlugIns/wireshark/4-x/epan/
        * INSTALLDIR/lib/wireshark/plugins/4-x/epan/
