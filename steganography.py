import hashlib
from PIL import Image
import os
import math
from Crypto.Cipher import AES
from Crypto.Util import Padding
from bitstring import BitArray
import sys

#returns image bytes
def load_image(image_file_path):
    im = Image.open(image_file_path)

    [size_x, size_y] = im.size

    return im.convert('RGBA')

def hash_image(image_file_path):
    
    with open(image_file_path, "rb") as f:
        digest = hashlib.file_digest(f, "sha256")

    return digest.digest()

def encrypt_message(image_hash: bytes, bytes_to_encrypt : bytes):

    #yes this is the most basic and very weak form of the encryption
    #but doesn't deal with random key generation
    cipher = AES.new(image_hash, AES.MODE_ECB)
    block_size = AES.block_size
    padded_bytes = Padding.pad(bytes_to_encrypt, block_size)

    return cipher.encrypt(padded_bytes)


def decrypt_message(image_hash: bytes, bytes_to_decrypt : bytes):
    
    cipher = AES.new(image_hash, AES.MODE_ECB)
    block_size = AES.block_size
    decrypted_bytes = Padding.unpad(cipher.decrypt(bytes_to_decrypt), block_size)
    
    return decrypted_bytes


def check_if_can_encode(bytes_size: bytes, total_pixels):
    
    #image must have enought bytes to encode everything
    if math.floor(total_pixels / 2) - 4 > bytes_size:
        return True
    return False

def load_message(file_path_message,):

    with open(file_path_message, "rb") as message_buffer:
        f = message_buffer.read()
        return bytearray(f)

#could inline this
def get_new_RGBA(RGBA_tuple: tuple, nibble: str):
    r = RGBA_tuple[0] ^ int(nibble[0])
    g = RGBA_tuple[1] ^ int(nibble[1])
    b = RGBA_tuple[2] ^ int(nibble[2])
    a = RGBA_tuple[3] ^ int(nibble[3])
    return (r,g,b,a)


def encode_message_into_image(image_pixels : Image, encrypted_message: bytes):
    length_of_message = len(encrypted_message)

    length_bit_string = '{:032b}'.format(length_of_message)

    bit_array: BitArray = BitArray(encrypted_message)
    bit_string = bit_array.bin
    string_to_encode = length_bit_string + bit_string

    cut_array =  [string_to_encode[i:i+4] for i in range(0, len(string_to_encode), 4)]

    [size_x, size_y] = image_pixels.size  

    for i in range(len(cut_array)):
        x = int(i % size_x)
        y = int(i / size_x)
        pixel_location = (x, y)
        
        [r,g,b,a] = image_pixels.getpixel(pixel_location)

        new_RGBA = get_new_RGBA((r,g,b,a), cut_array[i])

        image_pixels.putpixel(pixel_location, new_RGBA)
    
    return image_pixels

def encode_encrypted_message(image_file_path, message_file_path):

    image_pixels = load_image(image_file_path)

    image_hash_key = hash_image(image_file_path)
    
    #NOTE CHANGE THIS TO BE ANY KIND OF MESSAGE 

    total_pixels = image_pixels.size[0] * image_pixels.size[1]
    encoding : bytearray = load_message(message_file_path)

    message_encrypted: bytes = encrypt_message(image_hash_key, encoding)
    can_encode = check_if_can_encode(len(message_encrypted), total_pixels)

    if can_encode: 
        encode_message_into_image(image_pixels, message_encrypted)
        
        #image_pixels.show()
        image_pixels.save("encoded_" + image_file_path)

    else:
        print("Too much information in the message to encode!")

    return

#taken directly from stackoverflow - see source
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

#requires check for file type
def decode_encrypted_message(image_file_path, encrypted_image_file_path, output_file_path):
    
    image_pixels = load_image(image_file_path)

    image_hash_key = hash_image(image_file_path)

    encrypted_image_file = load_image(encrypted_image_file_path)

    [size_x, size_y] = image_pixels.size 

    image_length_pixels = [image_pixels.getpixel( (int(i%size_x), int(i/size_x)) ) for i in range(8)] #length is held in 32 bit in which takes 8 pixels
    message_length_pixels = [encrypted_image_file.getpixel( (int(i%size_x), int(i/size_x)) ) for i in range(8)] #length is held in 32 bit in which takes 8 pixels

    rgba_pixels_length = [get_new_RGBA(image_length_pixels[i], message_length_pixels[i]) for i in range(8)]

    length_bit_string = ""

    for i in range(8):
        for j in range(4):
            length_bit_string += bin(rgba_pixels_length[i][j])[2:]

    message_length_int = int(length_bit_string, 2)
    
    #need to convert to byte number here so 2*... 
    image_message_pixels = [image_pixels.getpixel( (int(i%size_x), int(i/size_x)) ) for i in range(8, 2*message_length_int + 8)]
    message_pixels = [encrypted_image_file.getpixel( (int(i%size_x), int(i/size_x)) ) for i in range(8, 2*message_length_int + 8)]

    rgba_pixels = [get_new_RGBA(image_message_pixels[i], message_pixels[i]) for i in range(2*message_length_int)]

    bit_string = ""

    for i in range(2*message_length_int):
        for j in range(4):
            bit_string += bin(rgba_pixels[i][j])[2:]

    something = bitstring_to_bytes(bit_string)

    message_decrypted: bytes = decrypt_message(image_hash_key, bitstring_to_bytes(bit_string))

    with open("decrypted_" + output_file_path, "wb") as binary_file:
        binary_file.write(message_decrypted)
   
    return

#format is mode -E or -e for exampe image file, message file

def main():

    mode = sys.argv[1]

    if not mode in ["-e", "-E", "-d", "-D"]:
        print("Encrypt or decrypt mode not specified properly")
        return
    else: 
        if (mode in ["-e", "-E"] and len(sys.argv) != 4) or (mode in ["-d", "-D"] and len(sys.argv) != 5):
            print("Error, wrong number of arguments")
            return

    image_file_path = sys.argv[2]

    if not os.path.isfile(image_file_path):
        print("Image path not found")
        return

    if not image_file_path.split(".")[1] == "png":
        print("Image file not a .png")
        return

    message_file = sys.argv[3]

    if not os.path.isfile(message_file):
        print("Message file not found")
        return
    
    if mode in ["-e", "-E"]:
        encode_encrypted_message(image_file_path, message_file)
    elif mode in ["-d", "-D"]:
        output_file_path = sys.argv[4]
        #here message file refers to the output file
        decode_encrypted_message(image_file_path, message_file, output_file_path)


#RUNNING INSTRUCTIONS
#Encoding must use png file - there is a maximum amount of information that can be encoded this way
#Encryption format is py .\steganography.py -e <image.png> <file_to_encode.sometype>
#Decryption format is py .\steganography.py -d <image.png> <encoded_image.png> <output_file.sometype>

#NOTE Code is not heavily optimized but still runs fairly quickly
        
#Arbitrary data can be encoded - any bytes works 
#The output_file should be given the same extension as the file_to_encode for proper formating - there is no
#   automatic file type detection

#default file path is same as working directory containing this script

if __name__ == "__main__":
    main()

