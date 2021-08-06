# Header Generator

We use TextX to parse our header files and generate our public API document.

Unfortunately tools like `pycparser` are unsuitable for this since they ignore
comments, including our Doxygen comments.

## How does this work?

If and only if you wish to re-generate the public header files, cd into this
directory and run the following:

```bash
python3 -m venv venv
source venv/bin/activate
pip install textx
./make_public_header.sh
# Inspect generated he.h
mv he.h ../public/he.h
```

## Run Tests
Currently, you can run the tests by doing:


```bash
python3 -m venv venv
source venv/bin/activate
pip install textx
python make_header.py /dev/null test/test.h > public_test.h
diff --ignore-blank-lines public_test.h test/fixture_public_test.h
# Expect no output
```

## Wait I don't want to run python...

Then don't! Unless you need to regenerate the public headers this code is inert.

