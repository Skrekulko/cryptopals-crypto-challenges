import pytest

#
#   01 - Convert hex to base64
#

from solutions import convert_hex_to_base64
def test_s01_c01() -> None:
    input = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    result = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    
    assert convert_hex_to_base64(input) == result

#
#   02 - Fixed XOR
#
    
from solutions import fixed_xor
def test_s01_c02() -> None:
    input1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    input2 = bytes.fromhex("686974207468652062756c6c277320657965")
    result = bytes.fromhex("746865206b696420646f6e277420706c6179")
    
    assert fixed_xor(input1, input2) == result

    
#
#   03 - Single-byte XOR cipher
#

from solutions import single_byte_xor_decipher
def test_s01_c03() -> None:
    input = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    result = b"Cooking MC's like a pound of bacon"
    
    assert single_byte_xor_decipher(input)[0] == result

#
#   04 - Detect single-character XOR
#

from solutions import detect_single_character_xor, load_ciphers
@pytest.mark.skip(reason = "Takes too long to complete.")
def test_s01_c04() -> None:
    file_name = "files/4.txt"
    result = b"Now that the party is jumping\n"
    
    assert detect_single_character_xor(load_ciphers(file_name))[0] == result

#
#   05 - Implement repeating-key XOR
#

from solutions import repeating_key_xor
def test_s01_c05() -> None:
    input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    result = bytes.fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    
    assert repeating_key_xor(input, key) == result
    
#
#   06 - Break repeating-key XOR
#

from solutions import decipher_repeating_xor, load_data
@pytest.mark.skip(reason = "Takes too long to complete.")
def test_s01_c06() -> None:
    file_name = "files/6.txt"
    result_plaintext = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
    result_key = b"Terminator X: Bring the noise"
    
    assert decipher_repeating_xor(load_data(file_name)) == (result_plaintext, result_key)
    
#
#   07 - AES in ECB mode
#

from solutions import decrypt_aes_ecb
def test_s01_c07() -> None:
    file_name = "files/7.txt"
    key = b"YELLOW SUBMARINE"
    result = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin'"
    
    assert decrypt_aes_ecb(load_data(file_name), key) == result
 
#
#   08 - Detect AES in ECB mode
#

from solutions import detect_repeated_blocks
def test_s01_c08() -> None:
    file_name = "files/8.txt"
    result = True
    
    assert detect_repeated_blocks(load_data(file_name), 16) == result
    
#
#   09 - Implement PKCS#7 padding
#

from solutions import pkcs7_padding
def test_s02_c01() -> None:
    input = b"YELLOW SUBMARINE"
    block_size = 20
    result = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    
    assert pkcs7_padding(input, block_size) == result
    
#
#   10 - Implement CBC mode
#

from solutions import decrypt_aes_cbc
def test_s02_c02() -> None:
    file_name = "files/10.txt"
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * 16
    result = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
    
    assert decrypt_aes_cbc(load_data(file_name), key, iv) == result

#
#   11 - An ECB/CBC detection oracle
#

from solutions import detect_aes_ecb_or_cbc, encrypt_oracle
def test_s02_c03() -> None:
    input = b"A" * 50
    result = encrypt_oracle(input)

    assert detect_aes_ecb_or_cbc(result[1])[0] == result[0]
    
#
#   12 - Byte-at-a-time ECB decryption (Simple)
#

from solutions import byte_at_a_time_ecb_decryption
@pytest.mark.skip(reason = "Takes too long to complete.")
def test_s02_c04() -> None:
    input = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    result = b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    
    assert byte_at_a_time_ecb_decryption(input) == result
    
#
#   13 - ECB cut-and-paste
#

from solutions import hijack_user_role
def test_s02_c05() -> None:
    result = b"email=AAAAAAAAAAAAA&uid=10&role=admin"

    assert hijack_user_role() == result
    