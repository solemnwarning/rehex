/* Reverse Engineer's Hex Editor
 * Copyright (C) 2019 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdio.h>

int main(int argc, char **argv)
{
	if(argc != 5)
	{
		fprintf(stderr, "Usage: %s <input file> <variable name> <output.c> <output.h>\n", argv[0]);
		return 1;
	}
	
	const char *input    = argv[1];
	const char *variable = argv[2];
	const char *output_c = argv[3];
	const char *output_h = argv[4];
	
	FILE *in = fopen(input, "rb");
	if(in == NULL)
	{
		fprintf(stderr, "Unable to open %s\n", input);
		return 1;
	}
	
	FILE *out_c = fopen(output_c, "w");
	if(out_c == NULL)
	{
		fprintf(stderr, "Unable to open %s\n", output_c);
		return 1;
	}
	
	FILE *out_h = fopen(output_h, "w");
	if(out_h == NULL)
	{
		fprintf(stderr, "Unable to open %s\n", output_h);
		return 1;
	}
	
	unsigned int input_size = 0;
	
	fprintf(out_c, "const unsigned char %s[] = {\n", variable);
	
	for(int c; (c = getc(in)) != EOF;)
	{
		if(input_size > 0)
		{
			fprintf(out_c, ", ");
			
			if((input_size % 20) == 0)
			{
				fprintf(out_c, "\n");
			}
		}
		
		fprintf(out_c, "%d", c);
		++input_size;
	}
	
	fprintf(out_c, "\n");
	fprintf(out_c, "};\n");
	
	fprintf(out_h, "#ifdef __cplusplus\n");
	fprintf(out_h, "extern \"C\" {\n");
	fprintf(out_h, "#endif\n");
	fprintf(out_h, "extern unsigned char %s[%u];\n", variable, input_size);
	fprintf(out_h, "#ifdef __cplusplus\n");
	fprintf(out_h, "}\n");
	fprintf(out_h, "#endif\n");
	
	fclose(out_h);
	fclose(out_c);
	fclose(in);
	
	return 0;
}
