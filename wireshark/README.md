## Wireshark Dissector For STAMP Test Packets

To use this Wireshark Dissector, copy[^orsomething] the [`stamp.lua`](./stamp.lua) file into the [Wireshark plugins folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html). 

[^orsomething]: Symbolic links and shortcuts will also do the trick!

### Contributing

We would love contributions to the dissector. Here are a (very incomplete) list of tasks that need to be accomplished:

1. Error handling: Malformed packets are not currently handled.
2. HMAC verification
3. Additional TLVs

### Building

Wireshark has a built-in Lua interpreter. There is no need to "recompile" the dissector code when changes are made. However, if Wireshark is running you need to reload the Lua plugins (either _Analyze_ -> _Reload Lua Plugins_ or _Ctrl-Shift-L_) after every change to the dissector code.

The dissector's code is commented according to the [LDoc](https://stevedonovan.github.io/ldoc/) specifications which means that `ldoc` will generate HTML-formatted documentation for the dissector's functions. To build the documentation, install LDoc and run

```console
$ ldoc wireshark/stamp.lua --all 
```

from the root directory of the Teaparty source code. The output files will be stored in the `doc` directory of the root directory of the Teaparty source code.