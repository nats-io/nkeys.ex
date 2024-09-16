defmodule Nkeys.Xkeys do
  @nonce_length 24

  def encrypt(%Nkeys.Keypair{private_key: private}, message, target_public_key) do
    #{boxed, _} = Kcl.box(m(), n(), ask(), bpk())
    nonce = :crypto.strong_rand_bytes(@nonce_length)
    decoded_pk = decode_public_xcurve(target_public_key)
    {boxed, _} = Kcl.box(message, nonce, private, decoded_pk)

    boxed
  end

  def decrypt(%Nkeys.Keypair{private_key: private}, message, source_public_key) do
    nonce = "" # extract from the sealed message? not sure how xkeys.go does this
    {unboxed, _} = Kcl.unbox(message, nonce, private, source_public_key)

    unboxed
  end

  defp decode_public_xcurve(public_xkey) do
    ""
  end
end
