# Cisco PFCP Wireshark Dissector

A modified version of PFCP dissector for Wireshark supporting Cisco private IE and
compressed format.

## Installation

MAC OS ARM Wireshark 4.0 plugin version 0.0.12a [download](http://www.gdnet.be/Wireshark/mac_cisco_pfcp_0.0.12a_arm.so)

Win64 Wireshark 4.2 plugin version 0.0.16 [download](https://github.com/dufourgilles/cisco_pfcp/releases/download/v0.0.16/cisco_pfcp_win64_0.0.16.dll)

Win64 Wireshark 4.4 plugin version 0.0.19 [download](https://github.com/dufourgilles/cisco_pfcp/releases/download/v0.0.19/win64_rel_4_4_cisco_pfcp_0.0.19.dll)

Win64 Wireshark 4.6 plugin version 0.0.19 [download](https://github.com/dufourgilles/cisco_pfcp/releases/download/v0.0.19/win64_rel_4_6_cisco_pfcp_0.0.19.dll)

MAC OS Intel Wireshark 4.2 plugin version 0.0.16 [download](https://github.com/dufourgilles/cisco_pfcp/releases/download/v0.0.16/macos_cisco_pfcp_0.0.16.so)

MAC OS Intel Wireshark 4.4 plugin version 0.0.17 [download](https://github.com/dufourgilles/cisco_pfcp/releases/download/v0.0.17/macos_intel_cisco_pfcp_0.0.17.so)

MAC OS ARM Wireshark 4.4 plugin version 0.0.19 [download](https://github.com/dufourgilles/cisco_pfcp/releases/download/v0.0.19/macos_arm_cisco_pfcp_0.0.19.so)

MAC OS ARM Wireshark 4.6 plugin version 0.0.19 [download](https://github.com/dufourgilles/cisco_pfcp/releases/download/v0.0.19/macos_arm46_cisco_pfcp_0.0.19.so)

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
