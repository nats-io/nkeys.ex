defmodule NKEYS.CRCTest do
  use ExUnit.Case, async: true
  import NKEYS.CRC, only: [compute: 1]

  test "computes the CRC of an empty string as 0x0000" do
    assert compute("") == 0x0000
  end

  test "computes the CRC of a space as 0x2462" do
    assert compute(" ") == 0x2462
  end

  test "computes the CRC of '123456789' as 0x31c3" do
    assert compute("123456789") == 0x31C3
  end

  test "computes the CRC of 'Lammert Bies' as 0xcec8" do
    assert compute("Lammert Bies") == 0xCEC8
  end

  test "computes the CRC of a prefix + public key" do
    assert compute(
             <<160, 149, 214, 253, 190, 243, 130, 228, 52, 183, 6, 5, 160, 9, 48, 193, 100, 225,
               242, 184, 109, 60, 7, 145, 51, 5, 75, 144, 234, 85, 58, 212, 98>>
           ) == 60251
  end
end
