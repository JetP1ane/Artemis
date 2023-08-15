# Artemis
Artemis - C++ Hell's Gate Syscall Extractor
https://labs.en1gma.co/malwaredevelopment/evasion/security/2023/08/05/syscalls.html

![example](/images/Animation.gif)

I used the `cl` compiler for Visual Studio and accessed it through the **x64 Native Tools Command Prompt**  
**To Compile & Run:**  
`cl /EHsc /FA artemis.cpp syscall.obj && artemis.exe NtProtectVirtualMemory`
