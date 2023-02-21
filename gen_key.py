from ecies import generate_key

pri = generate_key()

print(f"Private key: {pri.to_hex()}")

pub = pri.public_key

print(f"Public key:  {pub.format()}")