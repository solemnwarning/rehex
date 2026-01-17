/* Dummy program used to check compiler flags needed for Foundation framework. */

#import <Foundation/Foundation.h>

int main()
{
	NSString *home_directory = NSHomeDirectory();
	
	NSURL *url = [NSURL fileURLWithPath:[NSString stringWithCString:"filename" encoding:[NSString defaultCStringEncoding]]];
	[url retain];
	[url release];
	
	return 0;
}
