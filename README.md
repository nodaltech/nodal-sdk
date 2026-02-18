# Nodal SDK

A small utilitarian python library for interfacing with Nodal Cyberbrain

### Installation

To install nodal-sdk locally, navigate to the repo root and run
```bash
pip install -e .
```

After this, you should be able to import the nodal-sdk into your python projects

```python
from nodal_sdk import Mitigator
from nodal_sdk.types import MitigationRequest, MitigationResponse
```

### Framework Usage

Nodal-sdk interacts with the Cyberbrain in an event-driven manner, and expects an async event loop in which to run.
Structure your cyberbrain component code like this:

```python
import asyncio

async def main():
    # Your component code here
    pass

if __name__ == "__main__":
    asyncio.run(main())
```

### Handshaking and authentication

In order for you to integrate with the cyberbrain, your nodal-sdk component must first undergo auth - facilitated by the ghost process. This process happens in the following steps:

1. Nodal Ghost and Nodal Cyberbrain are running and connected
2. Your nodal-sdk component starts
3. Your nodal-sdk component sends a POST request to https://{ghost_uri}/api/components/handshake with a payload of
    ```json
    {
        "name": "string", // name of the component
        "component_type": "string", // type of the component
        "port": "number", // port number on which your component is running
        "token": "string", // a shared secret token within ghost config that authenticates potential components
        "public_key": "string" // the zmq ECC public key of your component
    }
    ```
4. The assuming successful validation, the ghost will respond with the following message
    ```json
    {
        "z85_public_key": "string" // the z85 public key of the nodal cyberbrain
    }
    ```
5. The SDK will create a `/curve` folder in the directory the process was started from, and store this publickey at:
    ```bash
    /.../process_dir/curve/brain/curve.pub
    ```
6. After responding to your nodal-sdk component, the ghost will alert Cyberbrain that a component has registered. Cyberbrain will then reach out to your component through an ECC encrypted connection
7. Upon receiving a connection request, your nodal-sdk component will validate cyberbrain's public key agaist the one it received from ghost, if authentication succeeds, the components will begin exchanging messages.


## Implementation Skeletons

- `base/mitigator.py`: base mitigator skeleton
- `base/reporter.py`: base reporter example
- `base/feeder.py`: base feeder exampe

You can view complete domain-specific examples in the `/examples` directory.

Happy hunting!
