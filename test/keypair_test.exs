defmodule Nkeys.KeypairTest do
  use ExUnit.Case

  describe "from_seed/1" do
    test "creates a struct from a valid seed" do
      assert {:ok, nkey} =
               Nkeys.Keypair.from_seed("SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")

      assert nkey.private_key != nil
      assert nkey.public_key != nil
    end

    test "should raise error when seed has bad padding" do
      assert {:error, :invalid_seed} =
               Nkeys.Keypair.from_seed("UAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")
    end

    test "should raise error with invalid seeds" do
      assert {:error, :invalid_seed} =
               Nkeys.Keypair.from_seed("AUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU")

      assert {:error, :invalid_seed} = Nkeys.Keypair.from_seed("")

      assert {:error, :invalid_seed} = Nkeys.Keypair.from_seed(" ")
    end

    test "should validate prefix bytes" do
      seeds = [
        "SNAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "SCAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "SOAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
      ]

      Enum.each(seeds, fn seed ->
        assert {:ok, _nkey} = Nkeys.Keypair.from_seed(seed)
      end)

      invalid_seeds = [
        "SDAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "SBAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
      ]

      Enum.each(invalid_seeds, fn seed ->
        assert {:error, :invalid_seed} = Nkeys.Keypair.from_seed(seed)
      end)

      invalid_seeds = [
        "PWAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU",
        "PMAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"
      ]

      Enum.each(invalid_seeds, fn seed ->
        assert {:error, :invalid_seed} = Nkeys.Keypair.from_seed(seed)
      end)
    end
  end

  describe "sign/2" do
    @seed "SUAMLK2ZNL35WSMW37E7UD4VZ7ELPKW7DHC3BWBSD2GCZ7IUQQXZIORRBU"

    test "from_seed" do
      nonce = "PXoWU7zWAMt75FY"
      {:ok, nkeys} = Nkeys.Keypair.from_seed(@seed)
      signed_nonce = Nkeys.Keypair.sign(nkeys, nonce)
      encoded_signed_nonce = Base.encode64(signed_nonce)

      assert encoded_signed_nonce ==
               "ZaAiVDgB5CeYoXoQ7cBCmq+ZllzUnGUoDVb8C7PilWvCs8XKfUchAUhz2P4BYAF++Dg3w05CqyQFRDiGL6LrDw=="
    end

    test "a second nonce" do
      nonce = "iBFByN3zQjAT7dQ"
      {:ok, nkeys} = Nkeys.Keypair.from_seed(@seed)
      signed_nonce = Nkeys.Keypair.sign(nkeys, nonce)
      encoded_signed_nonce = Base.url_encode64(signed_nonce)

      assert encoded_signed_nonce ==
               "kagPGrixaWS5yuHqw9nTQrda1Q376fK3fRCGtYdF4_w2aSk-4O7Ca0JM0qvzm69HH6MoMps2yF6Q0Qs830JZCA=="
    end
  end

  test "creating a public nkey" do
    {:ok, nkeys} = Nkeys.Keypair.from_seed(@seed)
    assert Nkeys.Keypair.public_key(nkeys) == "UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L"
  end
end
