#!/usr/bin/env python3
import argparse
import hashlib
import os
import random
from typing import Callable, List, Optional


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

    gen = Pwgen()

    num_pw = -1
    gen.flags = PW_DIGITS | PW_UPPERS
    do_columns = False

    pwgen_fn = gen.pw_phonemes
    rng = random.Random()
    gen.randrange = rng.randrange

    if os.isatty(1):
        do_columns = True

    if args.capitalize and args.no_capitalize:
        parser.error("Can't combine --capitalize and --no-capitalize")
    if args.capitalize:
        gen.flags |= PW_UPPERS
    if args.numerals and args.no_numerals:
        parser.error("Can't combine --numerals and --no-numerals")
    if args.numerals:
        gen.flags |= PW_DIGITS
    if args.symbols:
        gen.flags |= PW_SYMBOLS
    if args.num_passwords:
        num_pw = args.num_passwords
    if args.remove_chars:
        gen.remove = args.remove_chars
        pwgen_fn = gen.pw_rand
    if args.secure:
        pwgen_fn = gen.pw_rand
    if args.no_numerals:
        gen.flags &= ~PW_DIGITS
    if args.no_capitalize:
        gen.flags &= ~PW_UPPERS
    if args.sha1:
        pw_sha1_init(args.sha1, rng)
    if args.ambiguous:
        gen.flags |= PW_AMBIGUOUS
    if args.no_vowels:
        pwgen_fn = gen.pw_rand
        gen.flags |= PW_NO_VOWELS
    if args.pw_length is not None:
        gen.size = args.pw_length
        if gen.size < 5:
            pwgen_fn = gen.pw_rand
        if pwgen_fn is not gen.pw_rand:
            if gen.size <= 2:
                gen.flags &= ~PW_UPPERS
            if gen.size <= 1:
                gen.flags &= ~PW_DIGITS
    if args.num_pw is not None:
        num_pw = args.num_pw
    term_width = 80
    if do_columns:
        num_cols = term_width // (gen.size + 1)
        if num_cols == 0:
            num_cols = 1
    if num_pw < 0:
        num_pw = num_cols * 20 if do_columns else 1
    for i in range(num_pw):
        s = pwgen_fn()
        if not do_columns or (i % num_cols) == (num_cols - 1) or i == num_pw - 1:
            print(s)
        else:
            print(s, end=" ")


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


class Pwgen:

    size = 8
    flags: int
    remove = ""

    def __init__(self) -> None:
        self.randrange: Callable[[int], int]

    elements = {
        **{c: VOWEL for c in "aeiou"},
        **{c: VOWEL | DIPTHONG for c in "ae ah ai ee ei ie oh oo".split()},
        **{c: CONSONANT for c in "bcdfghjklmnprstvwxyz"},
        **{c: CONSONANT | DIPTHONG for c in "ch ph qu sh th".split()},
        **{c: CONSONANT | DIPTHONG | NOT_FIRST for c in "gh ng".split()},
    }.items()

    pw_digits = "0123456789"
    pw_uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pw_lowers = "abcdefghijklmnopqrstuvwxyz"
    pw_symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    pw_ambiguous = "B8G6I1l0OQDS5Z2"
    pw_vowels = "01aeiouyAEIOUY"

    def get_rand_chars(self) -> str:
        charsets = []
        if self.flags & PW_DIGITS:
            charsets.append(self.pw_digits)
        if self.flags & PW_UPPERS:
            charsets.append(self.pw_uppers)
        charsets.append(self.pw_lowers)
        if self.flags & PW_SYMBOLS:
            charsets.append(self.pw_symbols)
        chars = "".join(charsets)
        remove = self.remove

        if self.flags & PW_AMBIGUOUS:
            remove += self.pw_ambiguous
        if self.flags & PW_NO_VOWELS:
            remove += self.pw_vowels

        if remove:
            chars = "".join(c for c in chars if c not in remove)
        if (self.flags & PW_DIGITS) and not (set(chars) & set(self.pw_digits)):
            raise SystemExit("Error: No digits left in the valid set")
        if (self.flags & PW_UPPERS) and not (set(chars) & set(self.pw_uppers)):
            raise SystemExit("Error: No upper case letters left in the valid set")
        if (self.flags & PW_SYMBOLS) and not (set(chars) & set(self.pw_symbols)):
            raise SystemExit("Error: No symbols left in the valid set")
        if not chars:
            raise SystemExit("Error: No characters left in the valid set")
        return chars

    def pw_rand(self) -> str:
        chars = self.get_rand_chars()
        if self.flags & PW_AMBIGUOUS:
            assert not set(chars) & set(self.pw_ambiguous)
        if self.flags & PW_NO_VOWELS:
            assert not set(chars) & set(self.pw_vowels)
        res: List[str] = []
        while True:
            feature_flags = self.flags if self.size > 2 else 0
            del res[:]
            while len(res) < self.size:
                ch = chars[self.randrange(len(chars))]
                res.append(ch)
                if (feature_flags & PW_DIGITS) and ch in self.pw_digits:
                    feature_flags &= ~PW_DIGITS
                if (feature_flags & PW_UPPERS) and ch in self.pw_uppers:
                    feature_flags &= ~PW_UPPERS
                if (feature_flags & PW_SYMBOLS) and ch in self.pw_symbols:
                    feature_flags &= ~PW_SYMBOLS
            if not (feature_flags & (PW_UPPERS | PW_DIGITS | PW_SYMBOLS)):
                return "".join(res)

    def pw_phonemes(self) -> str:
        while True:
            s = self.pw_phonemes_try()
            if s is not None:
                return s

    def pw_phonemes_try(self) -> Optional[str]:
        res = ""
        feature_flags = self.flags
        prev = 0
        should_be = VOWEL if self.randrange(2) else CONSONANT
        first = True
        while len(res) < self.size:
            elem, flags = list(self.elements)[self.randrange(len(self.elements))]
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
            if len(elem) + len(res) > self.size:
                continue
            # OK, we found an element which matches our criteria,
            # let's do it!
            if self.flags & PW_UPPERS:
                if (first or (flags & CONSONANT)) and self.randrange(10) < 2:
                    elem = elem[0].upper() + elem[1:]
                    feature_flags &= ~PW_UPPERS
            if self.flags & PW_AMBIGUOUS:
                if set(elem) & set(self.pw_ambiguous):
                    continue
            res += elem
            # Time to stop?
            if len(res) >= self.size:
                break
            # Handle PW_DIGITS
            if self.flags & PW_DIGITS:
                if not first and self.randrange(10) < 3:
                    ch = str(self.randrange(10))
                    while (self.flags & PW_AMBIGUOUS) and ch in self.pw_ambiguous:
                        ch = str(self.randrange(10))
                    res += ch
                    feature_flags &= ~PW_DIGITS
                    first = True
                    prev = 0
                    should_be = VOWEL if self.randrange(2) else CONSONANT
                    continue
            # Handle PW_SYMBOLS
            if self.flags & PW_SYMBOLS:
                if not first and self.randrange(10) < 2:
                    ch = self.pw_symbols[self.randrange(len(self.pw_symbols))]
                    while (self.flags & PW_AMBIGUOUS) and ch in self.pw_ambiguous:
                        ch = self.pw_symbols[self.randrange(len(self.pw_symbols))]
                    res += ch
                    feature_flags &= ~PW_SYMBOLS
            if should_be == CONSONANT:
                should_be = VOWEL
            else:
                if (prev & VOWEL) or (flags & DIPTHONG) or (self.randrange(10) > 3):
                    should_be = CONSONANT
                else:
                    should_be = VOWEL
            prev = flags
            first = False
        if not (feature_flags & (PW_UPPERS | PW_DIGITS | PW_SYMBOLS)):
            return res
        return None


if __name__ == "__main__":
    main()
