from secrets import choice


def key_generator(
    length: int = 10,
    has_symbols: bool = True,
    has_digits: bool = True,
    has_uppercase: bool = True,
) -> str:

    SYMBOLS_RANGE = [33, 38]
    DIGITS_RANGE = [48, 57]
    UPPERCASE_RANGE = [65, 90]
    LOWERCASE_RANGE = [97, 122]

    pool = [i for i in range(LOWERCASE_RANGE[0], LOWERCASE_RANGE[1] + 1)]

    if has_symbols:
        pool.extend([i for i in range(SYMBOLS_RANGE[0], SYMBOLS_RANGE[1] + 1)])

    if has_digits:
        pool.extend([i for i in range(DIGITS_RANGE[0], DIGITS_RANGE[1] + 1)])

    if has_uppercase:
        pool.extend([i for i in range(UPPERCASE_RANGE[0], UPPERCASE_RANGE[1] + 1)])

    password = "".join([chr(choice(pool)) for _ in range(length)])

    return password
