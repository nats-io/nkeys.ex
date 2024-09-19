defmodule Nkeys.Xkeys do
  @nonce_size 24
  @xkeyversion1 "xkv1"

  # def encrypt(%Nkeys.Keypair{private_key: private}, message, target_public_key) do
  #   #{boxed, _} = Kcl.box(m(), n(), ask(), bpk())
  #   nonce = :crypto.strong_rand_bytes(@nonce_length)
  #   decoded_pk = decode_public_xcurve(target_public_key)
  #   {boxed, _} = Kcl.box(message, nonce, private, decoded_pk)

  #   boxed
  # end

  # def decrypt(%Nkeys.Keypair{private_key: private}, message, source_public_key) do
  #   nonce = "" # extract from the sealed message? not sure how xkeys.go does this
  #   {unboxed, _} = Kcl.unbox(message, nonce, private, source_public_key)

  #   unboxed
  # end


  defp seal(input, decoded_target_pk, decoded_our_sk) do
    # Generate a random 24-byte nonce
    nonce = :crypto.strong_rand_bytes(@nonce_size)

    # Perform authenticated encryption using the KCL box_seal function
    {sealed, _} =  Kcl.box(input, nonce, decoded_our_sk, decoded_target_pk)

    @xkeyversion1 <> nonce <> sealed

  end

  defp open(input, decoded_our_sk, decoded_sender_pk) do
    <<_version::size(4), nonce::size(@nonce_size), message::binary>> = input

    Kcl.unbox()
  end
end
