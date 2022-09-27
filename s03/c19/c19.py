#
#   19 - Break fixed-nonce CTR mode using substitutions
#

from helper_c19 import AES128CTR, repeating_key_xor, single_byte_xor_decipher
import codecs

strings = [
    b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    b"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    b"U2hlIHJvZGUgdG8gaGFycmllcnM/",
    b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    b"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
]

def c19(key, nonce):
    # Initialize New AES CTR
    ctr = AES128CTR(key, nonce)
    
    # Transform Strings Into Ciphertexts
    ciphertexts = [
        ctr.transform(
            codecs.decode(string, "base64")
        ) for string in strings
    ]
    
    keystream = b""
    for i in range(max(map(len, ciphertexts))):
        # Construct A Column Of nth Ciphertext Characters
        column = b""
        for ciphertext in ciphertexts:
            column += ciphertext[i].to_bytes(1, "little") if i < len(ciphertext) else b""
            
        # Break The Single Byte Using Frequency Analysis
        keystream += single_byte_xor_decipher(column)[1].to_bytes(1, "little")
    
    # Decrypt The Ciphertexts
    plaintexts = []
    for ciphertext in ciphertexts:
        plaintexts.append(repeating_key_xor(ciphertext, keystream))
    
    return plaintexts