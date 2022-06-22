# Minecraft PC wireshark dissector
  Dissector(parser) of Minecraft packets for wireshark

# Building
1. Install C++ compiler, CMake >=2.8, wireshark with zlib support and its headers
2. Generate project files
```
	mkdir build
	cd build
	cmake ..
```
3. Compile
>Linux: `make` in directory with generated files.

# Installing
>Gentoo system-wide: `sudo cp libMCPC_dissector.so /usr/lib64/wireshark/plugins/$WIRESHARK_VERSION/epan/mcpc.so`

>Gentoo user-wide: `mkdir -p ~/.local/lib/wireshark/plugins/$WIRESHARK_VERSION/epan && cp libMCPC_dissector.so ~/.local/lib/wireshark/plugins/$WIRESHARK_VERSION/epan/mcpc.so`
