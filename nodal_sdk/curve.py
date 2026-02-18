import os
from typing import Tuple

import zmq
from zmq.utils import z85


class Curve:
    @staticmethod
    def with_curve_keys(name: str) -> Tuple[str, str]:
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        pub_keyspace = os.path.join(namespace, "curve.pub")
        priv_keyspace = os.path.join(namespace, "curve.key")

        if not os.path.exists(pub_keyspace) or not os.path.exists(priv_keyspace):
            if os.path.exists(pub_keyspace):
                os.unlink(pub_keyspace)

            if os.path.exists(priv_keyspace):
                os.unlink(priv_keyspace)

            pub_key, priv_key = zmq.curve_keypair()
            pub_key = pub_key.decode("utf-8")
            priv_key = priv_key.decode("utf-8")

            with open(pub_keyspace, "w") as f:
                f.write(pub_key)
                f.flush()

            with open(priv_keyspace, "w") as f:
                f.write(priv_key)
                f.flush()

        pub = open(pub_keyspace, "r").read()
        priv = open(priv_keyspace, "r").read()

        return (pub, priv)

    @staticmethod
    def as_binary(keys: Tuple[str, str]) -> Tuple[bytes, bytes]:
        return tuple(z85.decode(k) for k in keys)

    @staticmethod
    def namespace(name: str) -> str:
        namespace = f"./curve/{name}/"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        return namespace

    @staticmethod
    def write_public_key(name: str, z85_key: str):
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        keyspace = os.path.join(namespace, "curve.pub")
        if os.path.exists(keyspace):
            os.unlink(keyspace)

        with open(keyspace, "w") as f:
            f.write(z85_key)
            f.flush()

    @staticmethod
    def write_brain_key(name: str, z85_key: str):
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            os.makedirs(namespace)

        keyspace = os.path.join(namespace, "brain.pub")
        if os.path.exists(keyspace):
            os.unlink(keyspace)

        with open(keyspace, "w") as f:
            f.write(z85_key)
            f.flush()

    @staticmethod
    def load_keyspace_public(name: str) -> str | None:
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            return None

        keyspace = os.path.join(namespace, "curve.pub")
        if not os.path.exists(keyspace):
            return None

        publickey = open(keyspace, "r").read()
        return publickey

    @staticmethod
    def load_keyspace_brain(name: str) -> str | None:
        namespace = f"./curve/{name}"
        if not os.path.exists(namespace):
            return None

        keyspace = os.path.join(namespace, "brain.pub")
        if not os.path.exists(keyspace):
            return None

        publickey = open(keyspace, "r").read()
        return publickey
