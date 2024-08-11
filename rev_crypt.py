import copy
import math
from random import choice

import rsa


def is_prime(num: int) -> bool:
    """
    Проверка числа на простоту

    :param: num: проверяемое число
    :return: True или False
    """

    prime = num > 1 and (num % 2 != 0 or num == 2) and (num % 3 != 0 or num == 3)
    i = 5
    d = 2

    while prime and i * i <= num:
        prime = num % i != 0
        i += d
        d = 6 - d  # чередование прироста 2 и 4: 5 + 2, 7 + 4, 11 + 2, и т.д.
    return prime


def gcd_and_simpl(n: int) -> int:
    """
    Возвращает простое число, взаимнопростое с аргументом

    :param n: Число для проверки
    :return: Случайное простое число взаимнопростое с проверяемым
    """

    result = [i for i in range(1, n + 1) if math.gcd(n, i) and is_prime(i) == 1]
    return choice(result)


def ascii_encode(message: str) -> list[int]:
    """
    Преобразует сообщение в список ASCII кодов

    :param message: Сообение для преобразования в список ASCII кодов
    :return: Список ASCII кодов
    """

    int_msg = []
    for character in message:
        int_msg.append(ord(character))
    return int_msg


def ascii_decode(int_msg: list[int]) -> str:
    """
    Преобразует список ASCII кодов в сообщение

    :param int_msg: Сообение для преобразования в список ASCII кодов
    :return: Список ASCII кодов
    """

    message = ""
    for encode_character in int_msg:
        message += chr(encode_character)
    return message


def mask(int_msg: list[int], masking_factor: int, e: int, n: int) -> list[int]:
    """
    Маскирование сообщения, представленного списком кодов

    :param int_msg: Сообщение для маскирования, представленное списком кодов
    :param masking_factor: Число, взаимнопростое с параметром n,
        обычно известно только стороне, производящей маскирование
    :param e: Открытая экспонента, первая часть открытого ключа RSA
    :param n: Простое число, вторая часть открытого ключа RSA
    :return: Список маскированных кодов
    """

    int_msg_ = copy.deepcopy(int_msg)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index]*pow(masking_factor, e, n), 1, n)
    return int_msg_


def demask(int_msg: list[int], masking_factor: int, n: int) -> list[int]:
    """
    Демаскирование сообщения, представленного списком кодов

    :param int_msg: Сообщение для демаскирования, представленное списком чисел
    :param masking_factor: Число, взаимнопростое с параметром n,
        обычно известно только стороне, производящей маскирование
    :param n: Простое число, часть открытого ключа RSA
    :return: Список демаскированных кодов
    """

    int_msg_ = copy.deepcopy(int_msg)
    m_ = pow(masking_factor, -1, n)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index] * m_, 1, n)
    return int_msg_


def sign(int_msg: list, d: int, n: int):
    """
    Криптографическая подпись сообщения, предствленного списком кодов

    :param int_msg: Сообщение для подписи, представленное списком кодов
    :param d: Закрытая экспонента, часть закрытого ключа RSA
    :param n: Простое число, вторая часть открытого ключа RSA
    :return: Список подписанных кодов
    """

    int_msg_ = copy.deepcopy(int_msg)
    for character_index in range(len(int_msg)):
        int_msg_[character_index] = pow(int_msg_[character_index], d, n)
    return int_msg_


def sign_check(int_msg: list, e: int, n: int):
    """
    Снимает криптографическую подпись

    :param int_msg: Сообщение для снятия подписи, представленное списком кодов
    :param e: Открытая экспонента, первая часть открытого ключа RSA
    :param n: Простое число, вторая часть открытого ключа RSA
    :return: Список кодов без подписи
    """
    return [pow(i, e, n) for i in int_msg]


if __name__ == '__main__':
    # Generate RSA keys
    izb_public_key, izb_private_key = rsa.newkeys(16)
    ik_public_key, ik_private_key = rsa.newkeys(16)

    m = gcd_and_simpl(ik_public_key.n)
    I = "Hello, World!"

    ascii_msg = ascii_encode(I).copy()
    mask_msg = mask(ascii_encode(I), m, ik_public_key.e, ik_public_key.n).copy()
    signed_masked_msg = sign(mask_msg, ik_private_key.d, ik_private_key.n).copy()
    demasked_msg = demask(signed_masked_msg, m, ik_public_key.n)
    encode_msg = sign_check(demasked_msg, ik_public_key.e, ik_public_key.n)
    msg = ascii_decode(encode_msg)

    print(f"msg in ascii: {ascii_msg}")
    print(f"masked msg in ascii: {mask_msg}")
    print(f"sign: {signed_masked_msg}")
    print(f"demasked: {demasked_msg}")
    print(f"msg: {encode_msg}")
    print(msg)
