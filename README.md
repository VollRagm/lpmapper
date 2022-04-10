# lpmapper
A mapper that maps shellcode into loaded large page drivers.

This concept requires you to set the `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\LargePageDrivers` in the registry. This project can be used to get around common detection methods imposed by kernel-mode anti-cheats, such as BattlEye or EasyAntiCheat.    
**Please read through [this blog post](https://vollragm.github.io/posts/abusing-large-page-drivers/) to find out how to use this project.**
