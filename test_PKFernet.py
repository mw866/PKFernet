from PKFernet import PKFernet


def test_loopback():
    """Test basic ecnryption and decryption"""
    # Sender sends the message
    msg = b'this is a test message'
    sender_pf = PKFernet(priv_keyring='sender/sender_priv_keyring.json', public_keyrings='receiver/receiver_pub_keyrings.json')
    ctx = sender_pf.encrypt(msg, receiver_name='receiver', receiver_enc_pub_key_alias='rsa.2048.1.enc.priv', sender_sign_header='rsa_with_sha256.2048.1', adata='', sign_also=True)
    print(str(ctx, 'utf-8'))
    # Receiver receives the message
    receiver_pf = PKFernet(priv_keyring='receiver/receiver_priv_keyring.json', public_keyrings='sender/sender_pub_keyrings.json')
    m = receiver_pf.decrypt(ctx, sender_name='sender', verfiy_also=True)

    assert (msg == m)


def test_export_pub_keys():
    """Test export public keys in JSON"""
    # Exporting sender public keys from private keys
    sender_pf = PKFernet(priv_keyring='sender/sender_priv_keyring.json', public_keyrings='receiver/receiver_pub_keyrings.json')
    sender_pub_key_json_export = sender_pf.export_pub_keys(key_alias_list=[])

    # Loading sender existing public keyring file
    with open('sender/sender_pub_keyrings.json', 'r', encoding='utf-8') as f:
        sender_pub_key_json_file = f.read()

    assert sender_pub_key_json_export.replace(' ', '') in sender_pub_key_json_file.replace(' ', '')


def test_cross_decryption():
    "Cross-testing decryption of brook's ciphertext and public key"
    with open('brook/ciphertext.txt', 'r', encoding='utf-8') as f:
        brook_ciphertext = f.read()
    brook_pf = PKFernet(priv_keyring='sender/sender_priv_keyring.json', public_keyrings='brook/public_key.json')
    msg = brook_pf.decrypt(brook_ciphertext, sender_name='brook', verfiy_also=True)
    assert msg == b'This is a simple message'


def test_cross_encryption():
    """Encrypting ciphtertext for cross testing by brook"""
    msg = b'this is a test message'
    sender_pf = PKFernet(priv_keyring='sender/sender_priv_keyring.json', public_keyrings='brook/public_key.json')
    ctx = sender_pf.encrypt(msg, receiver_name='brook', receiver_enc_pub_key_alias='rsa.2048.1.enc.priv', sender_sign_header='rsa_with_sha256.2048.1', adata='', sign_also=True)
    print(str(ctx, 'utf-8'))
    assert True
