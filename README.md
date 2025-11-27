# Big Shoes

Big Shoes is a standalone Final Fantasy 7 stepgraph viewer written in Python.

## Installation and Usage

This should now run on Linux (tested with Arch Linux and BizHawk). You may have to add your own key to the EMULATOR_MAP in hook_linux.py. For example, for me BizHawk was running inside mono, so I edited the line ""[Ee]mu[Hh]awk"" to simply say "mono".

To use this, you need to run the script as sudo, or else you won't get access to other windows. You can also theoretically compile this into a standalone big_shoes.bin, but starting this also requires you to run it as sudo.

To build as a standalone application, you will need `Nuitka`. Run the installer script `__build_bigshoes.bat` to build it `big_shoes.bin`.

### Connecting to FF7

To connect to an emulator, go to Connect > Connect to Emulator.

Select the emulator process and process ID from the first two boxes. Click "Show This Window" to make sure the correct process is being referred to. Make sure to select the correct version on the rightmost box.

To connect to the PC version, go to Connect > Connect to PC. If FF7 PC is running, it will connect.

To disconnect from FF7, go to Connect > Disconnect

### Watches

View watches with Window > Watches

### Stepgraph

View the stepgraph with Window > Stepgraph

Use the mouse wheel to move left or right. Shift + scroll to scroll faster. Ctrl + scroll to change the y-axis danger scale. Alt + scroll to show more or less of the graph at a time.
### Formation Extrapolator

Window > Formation Extrapolator.

This window displays the next 10 battle formations on this field.

### Formation List

Window > List Formation Types.

This window lists the possible formations on this field.

## Compatability

I only tested this version of Big Shoes with BizHawk 2.11
