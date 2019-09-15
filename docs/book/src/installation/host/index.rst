==================
Preparing the Host
==================

## Installation recommendations and scripts for optimal performance
1. For best compability we strongly suggest installing on [Ubuntu 18.04 LTS](https://ubuntu.com/#download)
2. [KVM](https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh) is recommended as hypervisor
 * `sudo ./kvm-qemu.sh all <username>`
3. To install CAPE itself, [cuckoo.sh](https://github.com/doomedraven/Tools/blob/master/Cuckoo/cuckoo.sh) with all optimizations
 * `sudo ./cuckoo.sh all cape`
4. Reboot and enjoy

\* All scripts contain __help__ `-h`, but please check the scripts to understand what they are doing.


