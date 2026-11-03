from bintriage.entropy import PACKED_THRESHOLD, is_packed, shannon_entropy


def test_zero_for_empty():
    assert shannon_entropy(b"") == 0.0


def test_zero_for_uniform():
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(b"A" * 50) == 0.0


def test_one_bit_for_two_equal_symbols():
    assert abs(shannon_entropy(b"AB" * 500) - 1.0) < 1e-9


def test_full_byte_range_is_eight_bits():
    data = bytes(range(256)) * 4
    assert abs(shannon_entropy(data) - 8.0) < 1e-9


def test_is_packed_threshold():
    assert not is_packed(PACKED_THRESHOLD - 0.1)
    assert is_packed(PACKED_THRESHOLD)
    assert is_packed(7.99)
