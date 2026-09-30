/* nRF52840 with the Adafruit nRF52 bootloader and SoftDevice S140 6.x.x
 * left in place (Feather nRF52840, nice!nano, Heltec T114, T-Echo, ...).
 *
 * 0x00000000  MBR
 * 0x00001000  S140 6.x.x: not used by the examples, kept for the bootloader
 * 0x00026000  application
 * 0x000EB000  STORAGE (bonding example)
 * 0x000ED000  left alone: Arduino InternalFS on these boards
 * 0x000F4000  bootloader, then its settings
 *
 * S140 7.x.x is 4K larger: use ORIGIN = 0x00027000 and shorten FLASH by 4K.
 * INFO_UF2.TXT on the bootloader drive names the SoftDevice version.
 * The first 8 bytes of RAM belong to the MBR.
 */
MEMORY
{
  FLASH   : ORIGIN = 0x00026000, LENGTH = 0xEB000 - 0x26000
  STORAGE : ORIGIN = 0x000EB000, LENGTH = 8K
  RAM     : ORIGIN = 0x20000008, LENGTH = 256K - 8
}

__storage_start = ORIGIN(STORAGE);
__storage_end = ORIGIN(STORAGE) + LENGTH(STORAGE);
