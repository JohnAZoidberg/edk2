#ifndef __serial_h__
#define __serial_h__

static __inline void
outb (UINT8 __value, UINT16 __port)
{
  __asm__ __volatile__ ("outb %b0,%w1": :"a" (__value), "Nd" (__port));
}

static __inline CHAR8
inb (UINT16 __port)
{
  UINT8 _v;

  __asm__ __volatile__ ("inb %w1,%0":"=a" (_v):"Nd" (__port));
  return _v;
}

#define PORT 0x3f8   /* COM1 */

#define DLAB		0x80

#define TXR             0       /*  Transmit register (WRITE) */
#define RXR             0       /*  Receive register  (READ)  */
#define IER             1       /*  Interrupt Enable          */
#define IIR             2       /*  Interrupt ID              */
#define FCR             2       /*  FIFO control              */
#define LCR             3       /*  Line control              */
#define MCR             4       /*  Modem control             */
#define LSR             5       /*  Line Status               */
#define MSR             6       /*  Modem Status              */
#define DLL             0       /*  Divisor Latch Low         */
#define DLH             1       /*  Divisor latch High        */

static int is_transmit_empty()
{
	return inb(PORT + 5) & 0x20;
}
 
static void serial_char(CHAR8 a) {
	outb(a, PORT);
	while (is_transmit_empty() == 0);
}

static void serial_string(CONST CHAR8 * s)
{
	while(*s)
		serial_char(*s++);
}

static void serial_hex(UINT64 x, UINTN digits)
{
	while(digits-- > 0)
	{
		UINTN d = (x >> (digits * 4)) & 0xF;
		if (d >= 0xA)
			serial_char(d + 'A' - 0xA);
		else
			serial_char(d + '0');
	}
	serial_char('\r');
	serial_char('\n');
}


#endif
