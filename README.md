# Artemis
Artemis - C++ Hell's Gate Syscall Extractor  

  
[**Blog Post**](https://labs.en1gma.co/malwaredevelopment/evasion/security/2023/08/14/syscalls.html)

![example](/images/Animation.gif)

- I used the `cl` compiler for Visual Studio and accessed it through the **x64 Native Tools Command Prompt**  

**To Run:**  
`artemis.exe <name_of_target_syscall>`

**To Compile & Run:**  
`cl /EHsc /FA artemis.cpp syscall.obj && artemis.exe <name_of_target_syscall>`

