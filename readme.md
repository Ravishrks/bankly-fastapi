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