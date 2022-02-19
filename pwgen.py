#!/usr/bin/env python3
import argparse
import hashlib
import os
import random
from typing import Callable, List


parser = argparse.ArgumentParser()
parser.add_argument("--alt-phonics", "-a", action="store_true")
parser.add_argument(
    "--capitalize",
    "-c",
    action="store_true",
    help="Include at least one capital letter in the password",
)
parser.add_argument(
    "--numerals",
    "-n",
    action="store_true",
    help="Include at least one number in the password",
)
parser.add_argument(
    "--symbols",
    "-y",
    action="store_true",
    help="Include at least one special symbol in the password",
)
parser.add_argument("--num-passwords", "-N")
parser.add_argument(
    "--remove-chars",
    "-r",
    help="Remove characters from the set of characters to generate passwords",
)
parser.add_argument(
    "--secure", "-s", action="store_true", help="Generate completely random passwords"
)
parser.add_argument(
    "--no-numerals",
    "-0",
    action="store_true",
    help="Don't include numbers in the password",
)
parser.add_argument(
    "--no-capitalize",
    "-A",
    action="store_true",
    help="Don't include capital letters in the password",
)
parser.add_argument(
    "--sha1", "-H", help="Use sha1 hash of given file as a (not so) random generator"
)
parser.add_argument(
    "--ambiguous",
    "-B",
    action="store_true",
    help="Don't include ambiguous characters in the password",
)
parser.add_argument(
    "--no-vowels",
    "-v",
    action="store_true",
    help="Do not use any vowels so as to avoid accidental nasty words",
)
parser.add_argument("pw_length", nargs="?", type=int)
parser.add_argument("num_pw", nargs="?", type=int)


PW_DIGITS = 0x0001  # At least one digit
PW_UPPERS = 0x0002  # At least one upper letter
PW_SYMBOLS = 0x0004
PW_AMBIGUOUS = 0x0008
PW_NO_VOWELS = 0x0010


def main() -> None:
    args = parser.parse_args()

    pw_length = 8
    num_pw = -1
    pwgen_flags = PW_DIGITS | PW_UPPERS
    do_columns = False

    pwgen_fn = pw_phonemes
    rng = random.Random()
    pw_number_fn = rng.randrange
    remove = ""

    if os.isatty(1):
        do_columns = True

    if args.capitalize and args.no_capitalize:
        parser.error("Can't combine --capitalize and --no-capitalize")
    if args.capitalize:
        pwgen_flags |= PW_UPPERS
    if args.numerals and args.no_numerals:
        parser.error("Can't combine --numerals and --no-numerals")
    if args.numerals:
        pwgen_flags |= PW_DIGITS
    if args.symbols:
        pwgen_flags |= PW_SYMBOLS
    if args.num_passwords:
        num_pw = args.num_passwords
    if args.remove_chars:
        remove = args.remove_chars
        pwgen_fn = pw_rand
    if args.secure:
        pwgen_fn = pw_rand
    if args.no_numerals:
        pwgen_flags &= ~PW_DIGITS
    if args.no_capitalize:
        pwgen_flags &= ~PW_UPPERS
    if args.sha1:
        pw_sha1_init(args.sha1, rng)
    if args.ambiguous:
        pwgen_flags |= PW_AMBIGUOUS
    if args.no_vowels:
        pwgen_fn = pw_rand
        pwgen_flags |= PW_NO_VOWELS
    if args.pw_length is not None:
        pw_length = args.pw_length
        if pw_length < 5:
            pwgen_fn = pw_rand
        if pwgen_fn != pw_rand:
            if pw_length <= 2:
                pwgen_flags &= ~PW_UPPERS
            if pw_length <= 1:
                pwgen_flags &= ~PW_DIGITS
    if args.num_pw is not None:
        num_pw = args.num_pw
    term_width = 80
    if do_columns:
        num_cols = term_width // (pw_length + 1)
        if num_cols == 0:
            num_cols = 1
    if num_pw < 0:
        num_pw = num_cols * 20 if do_columns else 1
    for i in range(num_pw):
        p = pwgen_fn(pw_length, pwgen_flags, remove, pw_number_fn)
        if not do_columns or (i % num_cols) == (num_cols - 1) or i == num_pw - 1:
            print(p)
        else:
            print(p, end=" ")


def pw_sha1_init(filename, rng) -> None:
    h = hashlib.sha1()
    with open(filename, "rb") as fp:
        while True:
            data = fp.read(2 ** 20)
            if not data:
                break
            h.update(data)
    rng.seed(h.digest())


CONSONANT = 0x0001
VOWEL = 0x0002
DIPTHONG = 0x0004
NOT_FIRST = 0x0008

elements = {
    "a": VOWEL,
    "ae": VOWEL | DIPTHONG,
    "ah": VOWEL | DIPTHONG,
    "ai": VOWEL | DIPTHONG,
    "b": CONSONANT,
    "c": CONSONANT,
    "ch": CONSONANT | DIPTHONG,
    "d": CONSONANT,
    "e": VOWEL,
    "ee": VOWEL | DIPTHONG,
    "ei": VOWEL | DIPTHONG,
    "f": CONSONANT,
    "g": CONSONANT,
    "gh": CONSONANT | DIPTHONG | NOT_FIRST,
    "h": CONSONANT,
    "i": VOWEL,
    "ie": VOWEL | DIPTHONG,
    "j": CONSONANT,
    "k": CONSONANT,
    "l": CONSONANT,
    "m": CONSONANT,
    "n": CONSONANT,
    "ng": CONSONANT | DIPTHONG | NOT_FIRST,
    "o": VOWEL,
    "oh": VOWEL | DIPTHONG,
    "oo": VOWEL | DIPTHONG,
    "p": CONSONANT,
    "ph": CONSONANT | DIPTHONG,
    "qu": CONSONANT | DIPTHONG,
    "r": CONSONANT,
    "s": CONSONANT,
    "sh": CONSONANT | DIPTHONG,
    "t": CONSONANT,
    "th": CONSONANT | DIPTHONG,
    "u": VOWEL,
    "v": CONSONANT,
    "w": CONSONANT,
    "x": CONSONANT,
    "y": CONSONANT,
    "z": CONSONANT,
}.items()


pw_digits = "0123456789"
pw_uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
pw_lowers = "abcdefghijklmnopqrstuvwxyz"
pw_symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
pw_ambiguous = "B8G6I1l0OQDS5Z2"
pw_vowels = "01aeiouyAEIOUY"


def pw_rand(size: int, pw_flags: int, remove: str, pw_number_fn: Callable[[int], int]) -> str:
    charsets = []
    if pw_flags & PW_DIGITS:
        charsets.append(pw_digits)
    if pw_flags & PW_UPPERS:
        charsets.append(pw_uppers)
    charsets.append(pw_lowers)
    if pw_flags & PW_SYMBOLS:
        charsets.append(pw_symbols)
    chars = "".join(charsets)
    if remove:
        if pw_flags & PW_AMBIGUOUS:
            remove += pw_ambiguous
        if pw_flags & PW_NO_VOWELS:
            remove += pw_vowels
        chars = "".join(c for c in chars if c not in remove)
        if (pw_flags & PW_DIGITS) and not (set(chars) & set(pw_digits)):
            raise SystemExit("Error: No digits left in the valid set")
        if (pw_flags & PW_UPPERS) and not (set(chars) & set(pw_uppers)):
            raise SystemExit("Error: No upper case letters left in the valid set")
        if (pw_flags & PW_SYMBOLS) and not (set(chars) & set(pw_symbols)):
            raise SystemExit("Error: No symbols left in the valid set")
        if not chars:
            raise SystemExit("Error: No characters left in the valid set")
    res: List[str] = []
    while True:
        feature_flags = pw_flags if size > 2 else 0
        del res[:]
        while len(res) < size:
            ch = chars[pw_number_fn(len(chars))]
            if (pw_flags & PW_AMBIGUOUS) and ch in pw_ambiguous:
                continue
            if (pw_flags & PW_NO_VOWELS) and ch in pw_vowels:
                continue
            res.append(ch)
            if (feature_flags & PW_DIGITS) and ch in pw_digits:
                feature_flags &= ~PW_DIGITS
            if (feature_flags & PW_UPPERS) and ch in pw_uppers:
                feature_flags &= ~PW_UPPERS
            if (feature_flags & PW_SYMBOLS) and ch in pw_symbols:
                feature_flags &= ~PW_SYMBOLS
        if not (feature_flags & (PW_UPPERS | PW_DIGITS | PW_SYMBOLS)):
            return "".join(res)


def pw_phonemes(size: int, pw_flags: int, remove: str, pw_number_fn: Callable[[int], int]) -> str:
    res: List[str] = []
    while True:
        del res[:]
        feature_flags = pw_flags
        c = 0
        prev = 0
        should_be = VOWEL if pw_number_fn(2) else CONSONANT
        first = True
        while c < size:
            elem, flags = list(elements)[pw_number_fn(len(elements))]
            # Filter on the basic type of the next element
            if (flags & should_be) == 0:
                continue
            # Handle the NOT_FIRST flag
            if first and (flags & NOT_FIRST):
                continue
            # Don't allow VOWEL followed a Vowel/Dipthong pair
            if (prev & VOWEL) and (flags & VOWEL) and (flags & DIPTHONG):
                continue
            # Don't allow us to overflow the buffer
            if len(elem) + c > size:
                continue
            # OK, we found an element which matches our criteria,
            # let's do it!
            if pw_flags & PW_UPPERS:
                if (first or (flags & CONSONANT)) and pw_number_fn(10) < 2:
                    elem = elem[0].upper() + elem[1:]
                    feature_flags &= ~PW_UPPERS
            if pw_flags & PW_AMBIGUOUS:
                if set(elem) & set(pw_ambiguous):
                    continue
            res.append(elem)
            c += len(elem)
            # Time to stop?
            if c >= size:
                break
            # Handle PW_DIGITS
            if pw_flags & PW_DIGITS:
                if not first and pw_number_fn(10) < 3:
                    ch = str(pw_number_fn(10))
                    while (pw_flags & PW_AMBIGUOUS) and ch in pw_ambiguous:
                        ch = str(pw_number_fn(10))
                    res.append(ch)
                    c += 1
                    feature_flags &= ~PW_DIGITS
                    first = True
                    prev = 0
                    should_be = VOWEL if pw_number_fn(2) else CONSONANT
                    continue
            # Handle PW_SYMBOLS
            if pw_flags & PW_SYMBOLS:
                if not first and pw_number_fn(10) < 2:
                    ch = pw_symbols[pw_number_fn(len(pw_symbols))]
                    while (pw_flags & PW_AMBIGUOUS) and ch in pw_ambiguous:
                        ch = pw_symbols[pw_number_fn(len(pw_symbols))]
                    res.append(ch)
                    c += 1
                    feature_flags &= ~PW_SYMBOLS
            if should_be == CONSONANT:
                should_be = VOWEL
            else:
                if (prev & VOWEL) or (flags & DIPTHONG) or (pw_number_fn(10) > 3):
                    should_be = CONSONANT
                else:
                    should_be = VOWEL
            prev = flags
            first = False
        if not (feature_flags & (PW_UPPERS | PW_DIGITS | PW_SYMBOLS)):
            return "".join(res)


if __name__ == "__main__":
    main()
