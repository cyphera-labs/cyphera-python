"""FF1 NIST SP 800-38G test vectors."""
from cyphera.ff1 import FF1, DIGITS, ALPHANUMERIC


def test_sample_1():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"), b"", DIGITS)
    assert c.encrypt("0123456789") == "2433477484"
    assert c.decrypt("2433477484") == "0123456789"


def test_sample_2():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"), bytes.fromhex("39383736353433323130"), DIGITS)
    assert c.encrypt("0123456789") == "6124200773"
    assert c.decrypt("6124200773") == "0123456789"


def test_sample_3():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C"), bytes.fromhex("3737373770717273373737"), ALPHANUMERIC)
    assert c.encrypt("0123456789abcdefghi") == "a9tv40mll9kdu509eum"
    assert c.decrypt("a9tv40mll9kdu509eum") == "0123456789abcdefghi"


def test_sample_4():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), b"", DIGITS)
    assert c.encrypt("0123456789") == "2830668132"
    assert c.decrypt("2830668132") == "0123456789"


def test_sample_5():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), bytes.fromhex("39383736353433323130"), DIGITS)
    assert c.encrypt("0123456789") == "2496655549"
    assert c.decrypt("2496655549") == "0123456789"


def test_sample_6():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), bytes.fromhex("3737373770717273373737"), ALPHANUMERIC)
    assert c.encrypt("0123456789abcdefghi") == "xbj3kv35jrawxv32ysr"
    assert c.decrypt("xbj3kv35jrawxv32ysr") == "0123456789abcdefghi"


def test_sample_7():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), b"", DIGITS)
    assert c.encrypt("0123456789") == "6657667009"
    assert c.decrypt("6657667009") == "0123456789"


def test_sample_8():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), bytes.fromhex("39383736353433323130"), DIGITS)
    assert c.encrypt("0123456789") == "1001623463"
    assert c.decrypt("1001623463") == "0123456789"


def test_sample_9():
    c = FF1(bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), bytes.fromhex("3737373770717273373737"), ALPHANUMERIC)
    assert c.encrypt("0123456789abcdefghi") == "xs8a0azh2avyalyzuwd"
    assert c.decrypt("xs8a0azh2avyalyzuwd") == "0123456789abcdefghi"
