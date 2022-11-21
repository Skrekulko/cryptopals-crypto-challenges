#
#   06 - Break repeating-key XOR
#

from cryptopals.s01.c06.solution_c06 import load_data, Decipher


def test_c06() -> None:
    # Name Of The Data File
    file_name = "6.txt"
    
    # Valid Result Plaintext
    result_plaintext =\
        b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn " \
        b"ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and " \
        b"the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug " \
        b"kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy " \
        b"posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd " \
        b"if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the " \
        b"stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and " \
        b"that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' " \
        b"wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and " \
        b"make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes " \
        b"atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can " \
        b"take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no " \
        b"denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, " \
        b"practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, " \
        b"no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! " \
        b"Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino " \
        b"\nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' " \
        b"\nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like " \
        b"Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this " \
        b"here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi " \
        b"\nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down " \
        b"\nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that " \
        b"\nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, " \
        b"'90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, " \
        b"so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, " \
        b"You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, " \
        b"Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- " \
        b"Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, " \
        b"everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, " \
        b"go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie " \
        b"and play that funky music till you die. \n\nPlay that funky music Come on, Come on, " \
        b"let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A " \
        b"little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that " \
        b"funky music \n"
    
    # Valid Result Key
    result_key = b"Terminator X: Bring the noise"
    
    assert Decipher.repeating_xor(load_data(file_name)) == (result_plaintext, result_key)
