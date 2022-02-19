pwgen.py - port of pwgen with multiple language models
======================================================

The [pwgen](https://github.com/tytso/pwgen) program by Theodore Ts'o
"generates passwords which are designed to be easily memorized by humans, while being as secure as possible."

It does so by building passwords from distinct sets of consonant and vowel elements,
each of which is either a single letter or one of the predefined two-letter combinations,
and adding capital letters, numerals, and symbols in-between.

This project is a reimplementation in Python
that makes it easy to define multiple language models.

The default language model is the English language model used in the original pwgen by Ts'o,
but a different one can be chosen with the `--language`/`-l` option.

The set of command-line options is otherwise the same as `pwgen`,
and the behavior is also the same, with the exception that a different
random number generator is used.

This project is a derivative of the GPL 2-licensed pwgen project,
and so is itself licensed under GPL 2.
