-module(rsa_ffi).
-export([extract_public_key_from_pem/1, extract_private_key_from_pem/1]).

extract_private_key_from_pem(PemBin) ->
    try
        PemEntries = public_key:pem_decode(PemBin),
        
        % Try PKCS#1 format first (RSAPrivateKey)
        case lists:keyfind('RSAPrivateKey', 1, PemEntries) of
            {_, DerCert, _} ->
                PrivateKey = public_key:der_decode('RSAPrivateKey', DerCert),
                {ok, PrivateKey};
            false ->
                % Try PKCS#8 format (PrivateKeyInfo)
                case lists:keyfind('PrivateKeyInfo', 1, PemEntries) of
                    Entry = {_, _, _} ->
                        % Use pem_entry_decode which handles the unwrapping automatically
                        PrivateKey = public_key:pem_entry_decode(Entry),
                        {ok, PrivateKey};
                    false ->
                        {error, nil}
                end
        end
    catch
        _:_ ->
            {error, nil}
    end.

extract_public_key_from_pem(PemBin) ->
    try
        PemEntries = public_key:pem_decode(PemBin),
        
        % Try to find a direct public key entry first
        case lists:keyfind('SubjectPublicKeyInfo', 1, PemEntries) of
            false ->
                % Try to find RSAPublicKey format
                case lists:keyfind('RSAPublicKey', 1, PemEntries) of
                    {_, DerCert, _} ->
                        PublicKey = public_key:der_decode('RSAPublicKey', DerCert),
                        {ok, PublicKey};
                    false ->
                        {error, nil}
                end;
            Entry ->
                PublicKey = public_key:pem_entry_decode(Entry),
                {ok, PublicKey}
        end
    catch
        _:_ ->
            {error, nil}
    end.
