import asyncio, websockets, json
from crypto import *

username = input("Username: ")

id_priv, id_pub = gen_identity()
dh_priv, dh_pub = gen_dh()

sessions = {}
peers = {}

async def chat():
    async with websockets.connect("ws://127.0.0.1:5555") as ws:
        await ws.send(username)
        await ws.send(dh_pub.public_bytes_raw().hex())

        async def receive():
            async for data in ws:
                msg = json.loads(data)

                if msg["type"] == "users":
                    for u, k in msg["data"].items():
                        if u != username:
                            peers[u] = bytes.fromhex(k)
                    print("\nUsers:", list(peers.keys()))
                else:
                    sender = msg["from"]

                    if sender not in sessions:
                        shared = kdf(
                            dh_priv.exchange(
                                x25519.X25519PublicKey.from_public_bytes(peers[sender])
                            )
                        )
                        sessions[sender] = Ratchet(shared)

                    try:
                        text = sessions[sender].decrypt(msg["nonce"], msg["msg"])
                        print(f"\n[{sender}] {text}")
                    except:
                        print("Decrypt failed")

        async def send():
            while True:
                to = input("\nTo: ").split(",")
                text = input("Message: ")

                for user in to:
                    user = user.strip()
                    if user not in peers:
                        continue

                    if user not in sessions:
                        shared = kdf(
                            dh_priv.exchange(
                                x25519.X25519PublicKey.from_public_bytes(peers[user])
                            )
                        )
                        sessions[user] = Ratchet(shared)

                    nonce, ct = sessions[user].encrypt(text)

                    await ws.send(json.dumps({
                        "from": username,
                        "to": [user],
                        "nonce": nonce,
                        "msg": ct
                    }))

        await asyncio.gather(receive(), send())

asyncio.run(chat())
