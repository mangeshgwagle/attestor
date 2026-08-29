# Third-party notices

## PayloadsAllTheThings-derived research corpus

`detector/darwin_payloads/payloads.json` contains defensive security research
material derived primarily from
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
alongside locally assembled examples inherited from the earlier Attestor corpus.
The exact upstream snapshot revision was not recorded by the original extractor.
The upstream project is distributed under the MIT License. Its notice is
reproduced below as required by that license.

> MIT License
>
> Copyright (c) 2019 Swissky
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

This notice covers that third-party material only. It does not grant or imply a
project-wide license for other Attestor files.

## Optional billing runtime and verification dependencies

Attestor does not vendor the billing service's Python dependencies. Operators fetch
them separately from their publishers using the exact versions in
`services/billing_api/requirements.txt` and `requirements-dev.txt`. Those
packages include Alembic, cryptography, FastAPI, psycopg, Pydantic, SQLAlchemy,
Stripe's official Python SDK, and Uvicorn. The verification environment also
uses HTTPX2 and pytest. Each installed package and transitive dependency remains
subject to its own license and notice metadata. Inclusion of a package name or
version here does not change its upstream license.
