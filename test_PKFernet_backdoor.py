
from PKFernet_backdoor import PKFernetBackdoor


def test_backdoor():
    """Test  encryption and decryption in the backdoor mode"""
    # Sender encrypts and sends the message in the backdoor mode
    msg = b'this is a test message'
    sender_pf = PKFernetBackdoor(priv_keyring='sender/sender_priv_keyring.json', public_keyrings='receiver/receiver_pub_keyrings.json')
    ctx = sender_pf.encrypt(msg, receiver_name='receiver', receiver_enc_pub_key_alias='rsa.2048.1.enc.priv', sender_sign_header='rsa_with_sha256.2048.1', adata='', sign_also=True, backdoor_mode=True)

    # The backdoor implementor (Brook) intercepts and decrypts the message in the backdoor mode
    # The `priv_keying` is not from the correct receiver and can be anyone's private key
    brook_pf = PKFernetBackdoor(priv_keyring='brook/private_key.json', public_keyrings='sender/sender_pub_keyrings.json')
    m = brook_pf.decrypt(ctx, sender_name='sender', verfiy_also=True, backdoor_mode=True)

    assert (msg == m)
