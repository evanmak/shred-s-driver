#Shred: S-driver

This is a linux module for a char device dmm, which means domain memory manager.
It should be noted that **it is only tested on Raspberry Pi 2 Model B, Cortex-A7, Linux Kernel version 4.1.15**. 

Also, DACR is deprecated in ARMv8. Interested user can find (Here)[https://gitlab.mpi-sws.org/vahldiek/erim] an alternarive approach of in-process memory isolation based on intel memory protection key (MPK).

## Publication

Our paper can be found in the [Shred - IEEES&P 2016](shred.pdf).

```
@inproceedings{chen2016shreds,
  title={Shreds: Fine-grained execution units with private memory},
  author={Chen, Yaohui and Reymondjohnson, Sebassujeen and Sun, Zhichuang and Lu, Long},
  booktitle={2016 IEEE Symposium on Security and Privacy (SP)},
  pages={56--71},
  year={2016},
  organization={IEEE}
}
```


## Credits 

- [Yaohui Chen](https://yaohway.github.io)
- [Zhichuang Sun](https://github.com/sunzc)
- [Sebassujeen Reymondjohnson](https://www.linkedin.com/in/sebassujeen/)
- [Long Lu](https://www.longlu.org)


## Disclaimer of Warranty
BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

