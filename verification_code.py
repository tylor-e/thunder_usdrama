#coding:utf-8
#this is a py27 file!

def file_path_verification_code_reader(path):
    def reader(image):
        with open(path, 'wb') as output:
            output.write(image)
        print 'Verification code picture is saved to %s, please open it manually and enter what you see.' % path
        code = raw_input('Verification code: ')
        return code
    return reader

# def ascii_verification_code_reader(image_data):
#     import ascii_verification_code_reader
#     print ascii_verification_code_reader.convert_to_ascii(image_data)
#     code = raw_input('Verification code: ')
#     return code

def default_verification_code_reader(reader_type, vcode_image_path):
    # if reader_type == 'ascii':
     #    return ascii_verification_code_reader

    if not vcode_image_path:
        vcode_image_path = './vcode.jpg'
    return file_path_verification_code_reader(vcode_image_path)

