# lpmapper
A mapper that maps shellcode into loaded large page drivers **without allocating any memory.**

This concept requires you to set the `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\LargePageDrivers` value in the registry. This project can be used to get around common detection methods imposed by kernel-mode anti-cheats, such as BattlEye or EasyAntiCheat.    
**Please read through [my blog post](https://vollragm.github.io/posts/abusing-large-page-drivers/) to find out how to use this project.**  

Parts of this projects are based on [kdmapper](https://github.com/TheCruZ/kdmapper).

[Newest release](https://github.com/VollRagm/lpmapper/releases/latest)
