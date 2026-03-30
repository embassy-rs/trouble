MEMORY
{
  /* NOTE 1 K = 1 KiBi = 1024 bytes */
  /* These values correspond to the NRF52840 */
  FLASH   : ORIGIN = 0x00000000, LENGTH = 1024K - 8K
  STORAGE : ORIGIN = 0x000FE000, LENGTH = 8K
  RAM     : ORIGIN = 0x20000000, LENGTH = 256K
}

__storage_start = ORIGIN(STORAGE);
__storage_end = ORIGIN(STORAGE) + LENGTH(STORAGE);
