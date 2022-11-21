#
#   10 - Implement CBC mode
#

from cryptopals.utils import load_data
from cryptopals.s02.c10.solution_c10 import AES128CBC


def test_c10() -> None:
    # Name Of The Data File
    file_name = "10.txt"

    # Secret Key
    key = b"YELLOW SUBMARINE"

    # Initialization Vector
    iv = b"\x00" * 16

    # Valid Result
    result =\
        b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the " \
        b"back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy " \
        b"\nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and " \
        b"I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! " \
        b"\n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at " \
        b"me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe " \
        b"girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- " \
        b"Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up " \
        b"and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious " \
        b"\nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and " \
        b"make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut " \
        b"you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a " \
        b"loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, " \
        b"you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, " \
        b"I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl " \
        b"stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' " \
        b"like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here " \
        b"song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the " \
        b"bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' " \
        b"tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and " \
        b"lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell " \
        b"it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the " \
        b"lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the " \
        b"witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me " \
        b"-- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, " \
        b"everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go " \
        b"\nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music " \
        b"till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white " \
        b"boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, " \
        b"white boy Come on, Come on, Come on \nPlay that funky music \n"
    
    assert AES128CBC.decrypt(load_data(file_name), key, iv) == result
