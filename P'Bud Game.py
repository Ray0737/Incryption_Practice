import base64

def secret_print(encoded):
    decoded = base64.b64decode(encoded).decode('utf-8')
    print(decoded)

def step1():
    print("Step 1: Decode this thing (ヒント: 🥚):")
    secret = [68, 117, 99, 107, 32, 101, 103, 103, 115] 
    result = ''.join(chr(c) for c in secret)
    guess = input("So... what's the magic word? ").strip() #Ans: Duck eggs
    if guess.lower() == result.lower():
        secret_print(b'8J+SqPCfkqTigJxPaG9ob35Db3JyZWN0ISBZb3UndmUgc21hcnRlciB0aGFuIHlvdSBsb29rIPCfmLkK\n')
        return True
    else:
        secret_print(b'8J+PiCDigJwgT29wcy4gVGhhdCBhaW4ndCBpdC4gR28gY3J5IGFuZCB0cnkgYWdhaW4u')
        return False

def step2():
    print("Step 2: Here's some fossil clues for ya 🍗")

    encoded_hints = [
        b'SSdtIHdoaXRlIGxpa2UgbGF1bmRyeSBwb3dkZXIu',
        b'SSBraW5kYSBsb29rIGxpa2UgY2hvcHN0aWNrcy4=',
        b'SSdtIGFzIHRhbGwgYXMgdW5lIGFuZCBhIGhhbGYgbWluaW9uICh5ZXMsIEkgbWVhc3VyZWQpLg==',
        b'UGh5c2ljcz8gTmFoLCBub3QgbXkgdGhpbmcu',
        b'SSBnaXZlIGJvaWxlZCBlZ2cgZW5lcmd5Lg==',
        b'TXkgbmFtZT8gVGhpbmsgb2YgdGhhdCBtb3VudGFpbiBwaWMgSSBvbmNlIHNlbnQgeW91Lg==',
        b'SSBIYXZlIGEgdGhpbmcgZm9yIFN0YXJidWNrcyBtYXRjaGEu',
        b'VGJoLCBhIGxvdCBvZiB5b3VyIGd1ZXNzZXMgYWJvdXQgbWUgd2VyZSBzcG90IG9uLg=='
    ]

    for i, e in enumerate(encoded_hints, 1):
        hint = base64.b64decode(e).decode()
        print(f"{i}. {hint}")

    input("\n(Press Enter when you're done giggling at my clues 😌)\n")
    return True

def caesar_decrypt(text, shift):
    result = ''
    for c in text:
        if c.islower():
            result += chr((ord(c) - shift - 97) % 26 + 97)
        elif c.isupper():
            result += chr((ord(c) - shift - 65) % 26 + 65)
        else:
            result += c
    return result

def step3():
    print("Step 3: Decode this mysterious password (ヒント: 🍜):")
    encrypted = "Fkrsvwlfnv"
    guess = input(f"Decode this word: {encrypted} → ").strip() #ANS = chopsticks
    correct = caesar_decrypt(encrypted, 3)
    if guess.lower() == correct.lower():
        secret_print(b'8J+SqPCfkqEiIFdob2F+IE5haWxlZCBpdCEgWW91J3JlIG9mZmljaWFsbHkgYSBub29kbGUgbWFzdGVyIPCfmI0K\n')
        return True
    else:
        secret_print(b'8J+YnyDjgYzwn42QIENsb3NlLi4uIGJ1dCBubyByYW1lbiBmb3IgeW91IHlldC4=')
        return False

def step4():
    secret_print(b'8J+olCBXb2FoISBZb3XigJ92ZSB1bmxvY2tlZCB0aGUgc3VwZXItc2VjcmV0IGZpbmFsZSDwn4eUIEJyYWNlIHlvdXJzZWxmIQ==')

    final_msg = base64.b64decode(
        b'SSDigJlzIGluIHRoZSB3YXJtLWNvbG9yIHRlYW0sIG15IG51bWJlcuKAmXMgYSBzaW5nbGUgZGlnaXQsIHdoaXRlIHNuZWFrZXJzIG9uIHBvaW50IC0tIGFuZCB5ZXAsIEkndmUgc2VlbiB5b3VyIGZhY2UgYmVmb3JlIPCfkKk='
    ).decode()

    note = base64.b64decode(
        b'U2F2ZSB0aGlzIG9yIHlvdSdsbCBoYXZlIHRvIHJ1biBpdCBhbGwgb3ZlciBhZ2Fpbj4gU2VlIHlvdSB0b21vcnJvdyEgSSdsbCBiZSB3YXRjaGluZyB0byBzZWUgaWYgeW91IGNhbiBmaW5kIG1lLiBHb29kIGx1Y2ssIGxpbCBvbmUg8J+Ypw=='
    ).decode()

    print(f"✨ Message: '{final_msg}'")
    print(f"P.S. {note}")

if __name__ == "__main__":
    if step1():
        if step2():
            if step3():
                step4()
