/* Dummy program used to check compiler flags needed for iconv. */

#include <iconv.h>
#include <string.h>

int main()
{
	iconv_t ic = iconv_open("foo", "bar");
	
	char in[1024] = "Hello", *ip = in;
	size_t il = strlen(in);
	
	char out[1024], *op = out;
	size_t ol = sizeof(out);
	
	iconv(ic, &ip, &il, &op, &ol);
	
	iconv_close(ic);
}
