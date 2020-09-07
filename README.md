# imgect: BMP/GIF Shellcode Injector

`imgect` will take shellcode (an explicit string or a payload file) and inject it into a valid BMP/GIF image. It will append the shellcode as secondary data to the end of the image which can then be extracted.

This tool can embed the shellcode into an existing GIF/BMP image file or create a new, valid GIF/BMP and embed the shellcode into it.

The injected shellcode can be extracted from the image by collecting all data between the following points:
```
2f 2f 2f 2f 2f  <-- ... -->  EOF-1

* The default delimiter is five (5) `/` that is used as a break point between the end
  of the image data and the beginnning of the shellcode.
* EOF-1 accounts for a final `;` being written to the end of the file.
```

During execution, imgect will output the offset of the payload within the file.

This tool is essentially a Python port of the following work:
* https://github.com/chinarulezzz/pixload/blob/master/bmp.pl
* https://github.com/chinarulezzz/pixload/blob/master/gif.pl

This tool is also heavily based on the following work:
* https://github.com/Urinx/SomeCodes/blob/master/Python/others/bmp-js-injector.py
* https://github.com/jhaddix/scripts/blob/master/gif_header_xss.py

The reason for this tool is to provide another quick Python solution to inject shellcode into a BMP/GIF image without corrupting it that will also allow basic encoding of the data being injected.

## Usage

```
usage: imgect.py [-h] (-g | -b) (-s SHELLCODE | -f FILE) [--encode] [-k KEY]
                 [-o OUTPUT] [--debug]

BMP/GIF Shellcode Injector -- v1.0

optional arguments:
  -h, --help            show this help message and exit

  -g, --gif             Inject into GIF image file

  -b, --bmp             Inject into BMP image file

  -s SHELLCODE, --shellcode SHELLCODE
                        Explicit shellcode to inject into the image

  -f FILE, --file FILE  Payload file containing shellcode

  --encode              Encode shellcode before injection

  -k KEY, --key KEY     Key to perform XOR encoding with

  -o OUTPUT, --output OUTPUT
                        Output image file (Default: payload.{gif|bmp})

  --debug               Enable debug output
```

### Generating a GIF

Pass a payload file:

```sh
python3 imgect.py --gif --file shellcode.bin --output image.gif
```

Pass an excplicit payload string:

```sh
python3 imgect.py --gif --shellcode 'Shellcode goes here' --output image.gif
```

### Generating a BMP

Pass a payload file:

```sh
python3 imgect.py --bmp --file shellcode.bin --output image.bmp
```

Pass an excplicit payload string:

```sh
python3 imgect.py --bmp --shellcode 'Shellcode goes here' --output image.bmp
```

### Examples

Direct injection of shellcode without encoding:

```
$ python3 imgect.py --gif --shellcode 'Shellcode goes here' --output image.gif --debug

*** BMP/GIF Shellcode Injector ***
               v1.0

[>]     Storing shellcode in memory
[*]     Shellcode contents size: 19 bytes
[>]     SHA256 Hash of original payload: c118268405bf9f3c2643081821d8aac4afa395ee32c3b3ef327df206d8f8863e 
[>]     Getting image data
[*]     Original image contents size: 26 bytes
[>]     Injecting shellcode into image
[+]     Payload was injected successfully
[*]     Malicious image contents size: 51 bytes

[+]     Index of payload: 31

00000000:  47 49 46 38 39 61 0a 00  0a 00 00 ff 00 2c 00 00  |GIF89a.......,..|
00000010:  00 00 0a 00 0a 00 00 02  00 3b 2f 2f 2f 2f 2f 53  |.........;/////S|
00000020:  68 65 6c 6c 63 6f 64 65  20 67 6f 65 73 20 68 65  |hellcode goes he|
00000030:  72 65 3b                                          |re;|
```

Inject encoded shellcode using a user-specified key:

```
$ python3 imgect.py --gif --shellcode 'Shellcode goes here' --output image.gif --encode \
  --key 'secret password' --debug

*** BMP/GIF Shellcode Injector ***
               v1.0

[>]     Storing shellcode in memory
[*]     Shellcode contents size: 19 bytes
[>]     SHA256 Hash of original payload: c118268405bf9f3c2643081821d8aac4afa395ee32c3b3ef327df206d8f8863e 
[>]     Base64 encoded key: c2VjcmV0IHBhc3N3b3Jk
[>]     Writing Base64 encoded XOR key to file: image.key
[>]     Encoding payload
[>]     Getting image data
[*]     Original image contents size: 26 bytes
[>]     Injecting shellcode into image
[+]     Payload was injected successfully
[*]     Malicious image contents size: 51 bytes

[+]     Index of payload: 31

00000000:  47 49 46 38 39 61 0a 00  0a 00 00 ff 00 2c 00 00  |GIF89a.......,..|
00000010:  00 00 0a 00 0a 00 00 02  00 3b 2f 2f 2f 2f 2f 20  |.........;///// |
00000020:  0d 06 1e 09 17 4f 14 04  53 14 18 0a 01 44 1b 00  |.....O..S....D..|
00000030:  11 17 3b                                          |..;|
```
