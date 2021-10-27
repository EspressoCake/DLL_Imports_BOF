# PE Import Enumerator BOF


## What is this?
This is a `BOF` to enumerate `DLL` files to-be-loaded by a given `PE` file.  Depending on the number of arguments, this will allow an operator to either view a listing of anticipated imported `DLL` files, or to view the imported functions for an anticipated `DLL`.


## Why?
At present, I was unaware of any existing `BOF` for `Cobalt Strike` to do such a thing.  As well, these sort of enumerators do exist, however they all rely on similar methods: downloading a given file and examining it on one's own workstation/endpoint/insert your favorite nomenclature here.

This aims to replace such manual activities while remaining ***ON*** the target endpoint itself.   We can do better, and should!

## How is this useful?
Simply, this is an additional datapoint available to an operator in terms of awareness within their target environment(s).  This will allow things to occur, such as further analysis with loaded modules within a running application, deducing such things as susceptibility to `DLL hijacking`, `DLL sideloading`, `DLL proxying`, etc.  The world is your oyster, now!


## What are the options this currently supports
- Option A:
	- `process_imports_api PATH_TO_TARGET_EXECUTABLE`
		e.g. `process_imports_api C:\Windows\System32\cmd.exe`
		
- Option B: 


## How do I make this operable?
1. In this case, you have two options:
	1. Use the existing, compiled object file, located in the `dist` directory (AKA proceed to major step two)
    2. Compile from source via the `Makefile`
        1. `cd src`
        2. `make clean`
        3. `make`
2. Load the `Aggressor` file, in the `Script Manager`, located in the `dist` directory


## Any known downsides?
- We're still using the `Win32` API and `Dynamic Function Resolution`.  This is for you to determine as far as "risk"
- You may attempt to incur a privileged action without sufficient requisite permissions.  I can't keep you from burning your hand.


## What does the output look like?
[Simple Output](https://i.ibb.co/zr3v6dg/dll-import1.png)
[Specific DLL Import Functions Output](https://i.ibb.co/Cz4s9bT/dll-import2.png)

## Whom would you like to credit?
[Duncan Ogilvie (@mrexodia)](https://twitter.com/mrexodia).  This wouldn't have come into fruition nearly as quickly without your existing code to reference.  Thank you for abstracting away the *pain* of the PE file format for me, seriously.
