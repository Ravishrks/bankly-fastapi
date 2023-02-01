# Bankly test server

## Start server

# Token
```
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
```

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 80
uvicorn main:app --reload --host 0.0.0.0 --port 8000 
```

## Using AES for encryption

We will use below package

```bash
pip install pycryptodome
```

## Handeling Requests in async way

```bash
pip install aiohttp 3.8.3
```