# Dependencies

The standalone review path uses Python 3.12, Node 26.7.0, `requirements-api.lock`, and `apps/web/package-lock.json`. CPU training adds the pinned `torch==2.14.1+cpu` wheel.

The required worker lock and activation helpers are bundled under `tools/`.

[Installation and commands](docs/reproduction.md) explain the dependency layers. [Fresh verification](docs/verification.md) records the tested installations and checks. Historical dependency notes are retained in [the development record](docs/development/DEPENDENCIES.original.md).
