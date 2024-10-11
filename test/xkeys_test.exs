defmodule NKEYS.XkeysTest do
  alias NKEYS.{Keypair, Xkeys}
  use ExUnit.Case

  describe "seal and unseal" do
    test "should round trip with no loss" do
      input = "this is top secret"
      alice = Keypair.new_user()
      bob = Keypair.new_user()

      sealed_data = Xkeys.seal(input, bob.public_key, alice.private_key)
      {:ok, unsealed_data} = Xkeys.open(sealed_data, alice.private_key, bob.public_key)

      assert "this is top secret" == unsealed_data
    end
  end
end
