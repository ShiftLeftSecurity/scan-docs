# Python secure coding

Scan bundles two python scanners:

- [custom scanner](https://github.com/ShiftLeftSecurity/sast-scan/tree/master/lib/pyt) that use AST and CFG to perform advanced security analysis. This scanner currently outperforms all other open-source SAST tools for python
- bandit - a basic AST based linter

## Custom scanner rules

- OWASP top 10 rules
- Security best practices for frameworks such as Flask, Django, aiohttp, pymongo and so on.

## Bandit rules

Following are some of the security checks performed and a description of remediation techniques and correct usages for certain modules.

B301: pickle
------------

Pickle and modules that wrap it can be unsafe when used to
deserialize untrusted data, possible security issue.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B301 | pickle              | - pickle.loads                     | Medium    |
|      |                     | - pickle.load                      |           |
|      |                     | - pickle.Unpickler                 |           |
|      |                     | - cPickle.loads                    |           |
|      |                     | - cPickle.load                     |           |
|      |                     | - cPickle.Unpickler                |           |
|      |                     | - dill.loads                       |           |
|      |                     | - dill.load                        |           |
|      |                     | - dill.Unpickler                   |           |
|      |                     | - shelve.open                      |           |
|      |                     | - shelve.DbfilenameShelf           |           |

Many common libraries that are often used for reading configuration files and deserializing objects are very dangerous because they can allow execution of arbitrary code. By default, libraries such as PyYAML and pickle do not provide strong separation of data and code, and thus allow code to be embedded inside the input.

Often the input to these libraries is untrusted or only partially trusted. These unsafe inputs can come from configuration files or be provided via REST APIs. For example, we often use YAML for configuration files but YAML files can also contain embedded Python code. This may provide an attacker with a method to execute code.

Many, but not all, of these libraries, offer safe interfaces that disable features that enable code execution. You always want to use the safe functions to load input. Often the obvious function to use is not the safe one and we should check the documentation for libraries not covered here.

We often use YAML, pickle, or eval to load data into our Python programs, but this is dangerous. PyYAML has a safe way to load code, but pickle and eval do not.

### Incorrect

yaml.load is the obvious function to use but it is dangerous:

```python
import yaml
import pickle
conf_str = '''
!!python/object:__main__.AttackerObj
key: 'value'
'''
conf = yaml.load(conf_str)
```

Using pickle or cPickle with untrusted input can result in arbitrary code execution.

```python
import pickle
import cPickle

user_input = "cos\nsystem\n(S'cat /etc/passwd'\ntR.'\ntR."
cPickle.loads(user_input) # results in code execution
pickle.loads(user_input)  # results in code execution
```

Similarly eval and exec are difficult to use safely with input that comes from an untrusted source.

```python
user_input = "os.system('cat /etc/passwd')"
eval(user_input) # execute python expressions

user_input = "import os; os.system('cat /etc/passwd')"
exec(user_input) # execute _any_ python code
```

### Correct

Here we use PyYAMLs safe YAML loading function:

```python
import yaml
conf_str = '''
- key: 'value'
- key: 'value'
'''
conf = yaml.safe_load(conf_str)
```

There is no safe alternative for pickle.load. However in most cases using pickle for serialization of data objects is something that can be avoided altogether.

B302: marshal
-------------

Deserialization with the marshal module is possibly dangerous.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B302 | marshal             | - marshal.load                     | Medium    |
|      |                     | - marshal.loads                    |           |

B303: md5
---------

Use of insecure MD2, MD4, MD5, or SHA1 hash function.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B303 | md5                 | - hashlib.md5                      | Medium    |
|      |                     | - hashlib.sha1                     |           |
|      |                     | - Crypto.Hash.MD2.new              |           |
|      |                     | - Crypto.Hash.MD4.new              |           |
|      |                     | - Crypto.Hash.MD5.new              |           |
|      |                     | - Crypto.Hash.SHA.new              |           |
|      |                     | - Cryptodome.Hash.MD2.new          |           |
|      |                     | - Cryptodome.Hash.MD4.new          |           |
|      |                     | - Cryptodome.Hash.MD5.new          |           |
|      |                     | - Cryptodome.Hash.SHA.new          |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .hashes.MD5                      |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .hashes.SHA1                     |           |

B304 - B305: ciphers and modes
------------------------------

Use of insecure cipher or cipher mode. Replace with a known secure cipher such
as AES.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B304 | ciphers             | - Crypto.Cipher.ARC2.new           | High      |
|      |                     | - Crypto.Cipher.ARC4.new           |           |
|      |                     | - Crypto.Cipher.Blowfish.new       |           |
|      |                     | - Crypto.Cipher.DES.new            |           |
|      |                     | - Crypto.Cipher.XOR.new            |           |
|      |                     | - Cryptodome.Cipher.ARC2.new       |           |
|      |                     | - Cryptodome.Cipher.ARC4.new       |           |
|      |                     | - Cryptodome.Cipher.Blowfish.new   |           |
|      |                     | - Cryptodome.Cipher.DES.new        |           |
|      |                     | - Cryptodome.Cipher.XOR.new        |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .ciphers.algorithms.ARC4         |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .ciphers.algorithms.Blowfish     |           |
|      |                     | - cryptography.hazmat.primitives   |           |
|      |                     |   .ciphers.algorithms.IDEA         |           |
|------|---------------------|------------------------------------|-----------|
| B305 | cipher_modes        | - cryptography.hazmat.primitives   | Medium    |
|      |                     |   .ciphers.modes.ECB               |           |

B306: mktemp_q
--------------

Use of insecure and deprecated function (mktemp).

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B306 | mktemp_q            | - tempfile.mktemp                  | Medium    |

Often we want to create temporary files to save data that we can’t hold in memory or to pass to external programs that must read from a file. The obvious way to do this is to generate a unique file name in a common system temporary directory such as /tmp, but doing so correctly is harder than it seems. Safely creating a temporary file or directory means following a number of rules (see the references for more details). We should never do this ourselves but use the correct existing library function. We also must take care to cleanup our temporary files even in the face of errors.

If we don’t take all these precautions we open ourselves up to a number of dangerous security problems. Malicious users that can predict the file name and write to directory containing the temporary file can effectively hijack the temporary file by creating a symlink with the name of the temporary file before the program creates the file itself. This allows a malicious user to supply malicious data or cause actions by the program to affect attacker chosen files. The references have more extensive descriptions of potential dangers.

Most programming lanuages provide functions to create temporary files. However, some of these functions are unsafe and should not be used. We need to be careful to use the safe functions.

Despite the safer temporary file creation APIs we must still be aware of where we are creating tempory files. Generally, temporary files should always be created on the local filesystem. Many remote filesystems (for example, NFSv2) do not support the open flags needed to safely create temporary files.

| Use | Avoid |
|-----|-------|
| tempfile.TemporaryFile | tempfile.mktemp |
| tempfile.NamedTemporaryFile | open |
| tempfile.SpoolTemporaryFile | |
| tempfile.mkstemp | |
| tempfile.mkdtemp | |

### Incorrect

Creating temporary files with predictable paths leaves them open to time of check, time of use attacks (TOCTOU). Given the following code snippet an attacker might pre-emptively place a file at the specified location.

```python
import os
import tempfile

# This will most certainly put you at risk
tmp = os.path.join(tempfile.gettempdir(), filename)
if not os.path.exists(tmp):
    with open(tmp, "w") file:
        file.write("defaults")
```

There is also an insecure method within the Python standard library that cannot be used in a secure way to create temporary file creation.

```python
import os
import tempfile

open(tempfile.mktemp(), "w")
```

Finally there are many ways we could try to create a secure filename that will not be secure and is easily predictable.

```
filename = "{}/{}.tmp".format(tempfile.gettempdir(), os.getpid())
open(filename, "w")
```


### Correct

The Python standard library provides a number of secure ways to create temporary files and directories. The following are examples of how you can use them.

Creating files:

```python
import os
import tempfile

# Use the TemporaryFile context manager for easy clean-up
with tempfile.TemporaryFile() as tmp:
    # Do stuff with tmp
    tmp.write('stuff')

# Clean up a NamedTemporaryFile on your own
# delete=True means the file will be deleted on close
tmp = tempfile.NamedTemporaryFile(delete=True)
try:
    # do stuff with temp
    tmp.write('stuff')
finally:
    tmp.close()  # deletes the file

# Handle opening the file yourself. This makes clean-up
# more complex as you must watch out for exceptions
fd, path = tempfile.mkstemp()
try:
    with os.fdopen(fd, 'w') as tmp:
        # do stuff with temp file
        tmp.write('stuff')
finally:
    os.remove(path)
```

We can also safely create a temporary directory and create temporary files inside it. We need to set the umask before creating the file to ensure the permissions on the file only allow the creator read and write access.

```python
import os
import tempfile

tmpdir = tempfile.mkdtemp()
predictable_filename = 'myfile'

# Ensure the file is read/write by the creator only
saved_umask = os.umask(0077)

path = os.path.join(tmpdir, predictable_filename)
print path
try:
    with open(path, "w") as tmp:
        tmp.write("secrets!")
except IOError as e:
    print 'IOError'
else:
    os.remove(path)
finally:
    os.umask(saved_umask)
    os.rmdir(tmpdir)
```

B309: httpsconnection
---------------------

Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do
not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B309 | httpsconnection     | - httplib.HTTPSConnection          | Medium    |
|      |                     | - http.client.HTTPSConnection      |           |
|      |                     | - six.moves.http_client            |           |
|      |                     |   .HTTPSConnection                 |           |

When developing a module that makes secure HTTPS connections, use a library that verifies certificates. Many such libraries also provide an option to ignore certificate verification failures. These options should be exposed to the OpenStack deployer to choose their level of risk.

Although the title of this guideline calls out HTTPS, verifying the identity of the hosts you are connecting to applies to most protocols (SSH, LDAPS, etc).

### Incorrect

```python
import requests
requests.get('https://www.slscan.io/', verify=False)
```

The example above uses `verify=False` to bypass the check of the certificate received against those in the CA trust store.

It is important to note that modules such as httplib within the Python standard library did not verify certificate chains until it was fixed in 2.7.9 release. For more specifics about the modules affected refer to [CVE-2014-9365](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-9365).

### Correct

```python
import requests
requests.get('https://www.slscan.io/', verify=CONF.ca_file)
```

The example above uses the variable CONF.ca_file to store the location of the CA trust store, which is used to confirm that the certificate received is from a trusted authority.


B310: urllib_urlopen (Unused)
--------------------

Audit url open for permitted schemes. Allowing use of 'file:'' or custom
schemes is often unexpected.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B310 | urllib_urlopen      | - urllib.urlopen                   | Medium    |
|      |                     | - urllib.request.urlopen           |           |
|      |                     | - urllib.urlretrieve               |           |
|      |                     | - urllib.request.urlretrieve       |           |
|      |                     | - urllib.URLopener                 |           |
|      |                     | - urllib.request.URLopener         |           |
|      |                     | - urllib.FancyURLopener            |           |
|      |                     | - urllib.request.FancyURLopener    |           |
|      |                     | - urllib2.urlopen                  |           |
|      |                     | - urllib2.Request                  |           |
|      |                     | - six.moves.urllib.request.urlopen |           |
|      |                     | - six.moves.urllib.request         |           |
|      |                     |   .urlretrieve                     |           |
|      |                     | - six.moves.urllib.request         |           |
|      |                     |   .URLopener                       |           |
|      |                     | - six.moves.urllib.request         |           |
|      |                     |   .FancyURLopener                  |           |

It is common for web forms to redirect to a different page upon successful submission of the form data. This is often done using a next or return parameter in the HTTP request. Any HTTP parameter can be controlled by the user, and could be abused by attackers to redirect a user to a malicious site.

This is commonly used in phishing attacks, for example an attacker could redirect a user from a legitimate login form to a fake, attacker controlled, login form. If the page looks enough like the target site, and tricks the user into believing they mistyped their password, the attacker can convince the user to re-enter their credentials and send them to the attacker.

Here is an example of a malicious redirect URL:

https://good.com/login.php?next=http://bad.com/phonylogin.php

To counter this type of attack all URLs must be validated before being used to redirect the user. This should ensure the redirect will take the user to a page within your site.

### Incorrect

This example just processes the ‘next’ argument with no validation:

```python
import os
from flask import Flask,redirect, request

app = Flask(__name__)

@app.route('/')
def example_redirect():
    return redirect(request.args.get('next'))
```

### Correct

The following is an example using the Flask web framework. It checks that the URL the user is being redirected to originates from the same host as the host serving the content.

```python
from flask import request, g, redirect
from urlparse import urlparse, urljoin


def is_safe_redirect_url(target):
  host_url = urlparse(request.host_url)
  redirect_url = urlparse(urljoin(request.host_url, target))
  return redirect_url.scheme in ('http', 'https') and \
    host_url.netloc == redirect_url.netloc


def get_safe_redirect():
  url =  request.args.get('next')
  if url and is_safe_redirect_url(url):
    return url

  url = request.referrer
  if url and is_safe_redirect_url(url):
    return url

  return '/'
```

The Django framework contains a `django.utils.http.is_safe_url` function that can be used to validate redirects without implementing a custom version.


B311: random
------------

Standard pseudo-random generators are not suitable for security/cryptographic
purposes.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B311 | random              | - random.random                    | Low       |
|      |                     | - random.randrange                 |           |
|      |                     | - random.randint                   |           |
|      |                     | - random.choice                    |           |
|      |                     | - random.uniform                   |           |
|      |                     | - random.triangular                |           |

B312: telnetlib
---------------

Telnet-related functions are being called. Telnet is considered insecure. Use
SSH or some other encrypted protocol.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B312 | telnetlib           | - telnetlib.\*                     | High      |

B313 - B320: XML
----------------

Using various XLM methods to parse untrusted XML data is known to be vulnerable
to XML attacks. Methods should be replaced with their defusedxml equivalents.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B313 | xml_bad_cElementTree| - xml.etree.cElementTree.parse     | Medium    |
|      |                     | - xml.etree.cElementTree.iterparse |           |
|      |                     | - xml.etree.cElementTree.fromstring|           |
|      |                     | - xml.etree.cElementTree.XMLParser |           |
|------|---------------------|------------------------------------|-----------|
| B314 | xml_bad_ElementTree | - xml.etree.ElementTree.parse      | Medium    |
|      |                     | - xml.etree.ElementTree.iterparse  |           |
|      |                     | - xml.etree.ElementTree.fromstring |           |
|      |                     | - xml.etree.ElementTree.XMLParser  |           |
|------|---------------------|------------------------------------|-----------|
| B315 | xml_bad_expatreader | - xml.sax.expatreader.create_parser| Medium    |
|------|---------------------|------------------------------------|-----------|
| B316 | xml_bad_expatbuilder| - xml.dom.expatbuilder.parse       | Medium    |
|      |                     | - xml.dom.expatbuilder.parseString |           |
|------|---------------------|------------------------------------|-----------|
| B317 | xml_bad_sax         | - xml.sax.parse                    | Medium    |
|      |                     | - xml.sax.parseString              |           |
|      |                     | - xml.sax.make_parser              |           |
|------|---------------------|------------------------------------|-----------|
| B318 | xml_bad_minidom     | - xml.dom.minidom.parse            | Medium    |
|      |                     | - xml.dom.minidom.parseString      |           |
|------|---------------------|------------------------------------|-----------|
| B319 | xml_bad_pulldom     | - xml.dom.pulldom.parse            | Medium    |
|      |                     | - xml.dom.pulldom.parseString      |           |
|------|---------------------|------------------------------------|-----------|
| B320 | xml_bad_etree       | - lxml.etree.parse                 | Medium    |
|      |                     | - lxml.etree.fromstring            |           |
|      |                     | - lxml.etree.RestrictedElement     |           |
|      |                     | - lxml.etree.GlobalParserTLS       |           |
|      |                     | - lxml.etree.getDefaultParser      |           |
|      |                     | - lxml.etree.check_docinfo         |           |

B321: ftplib
------------

FTP-related functions are being called. FTP is considered insecure. Use
SSH/SFTP/SCP or some other encrypted protocol.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B321 | ftplib              | - ftplib.\*                        | High      |

B323: unverified_context
------------------------

By default, Python will create a secure, verified ssl context for use in such
classes as HTTPSConnection. However, it still allows using an insecure
context via the _create_unverified_context that reverts to the previous
behavior that does not validate certificates or perform hostname checks.

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B323 | unverified_context  | - ssl._create_unverified_context   | Medium    |

B325: tempnam
--------------

Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider
using tmpfile() instead.

!!! Tip
    For further information:

    - [https://docs.python.org/2.7/library/os.html#os.tempnam](https://docs.python.org/2.7/library/os.html#os.tempnam)
    - [https://docs.python.org/3/whatsnew/3.0.html?highlight-tempnam](https://docs.python.org/3/whatsnew/3.0.html?highlight-tempnam)
    - [https://bugs.python.org/issue17880](https://bugs.python.org/issue17880)

| ID   |  Name               |  Calls                             |  Severity |
|------|---------------------|------------------------------------|-----------|
| B325 | tempnam             | - os.tempnam                       | Medium    |
|      |                     | - os.tmpnam                        |           |

B401: import_telnetlib
----------------------

A telnet-related module is being imported. Telnet is considered insecure. Use
SSH or some other encrypted protocol.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B401 | import_telnetlib    | - telnetlib                        | High      |

B402: import_ftplib
-------------------
A FTP-related module is being imported.  FTP is considered insecure. Use
SSH/SFTP/SCP or some other encrypted protocol.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B402 | import_ftplib       | - ftplib                           | High      |

B403: import_pickle
-------------------

Consider possible security implications associated with these modules.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B403 | import_pickle       | - pickle                           | Low       |
|      |                     | - cPickle                          |           |
|      |                     | - dill                             |           |
|      |                     | - shelve                           |           |


B405: import_xml_etree
----------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B405 | import_xml_etree    | - xml.etree.cElementTree           | Low       |
|      |                     | - xml.etree.ElementTree            |           |

B406: import_xml_sax
--------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B406 | import_xml_sax      | - xml.sax                          | Low       |

B407: import_xml_expat
----------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B407 | import_xml_expat    | - xml.dom.expatbuilder             | Low       |

B408: import_xml_minidom
------------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B408 | import_xml_minidom  | - xml.dom.minidom                  | Low       |

B409: import_xml_pulldom
------------------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package,
or make sure defusedxml.defuse_stdlib() is called.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B409 | import_xml_pulldom  | - xml.dom.pulldom                  | Low       |

B410: import_lxml
-----------------

Using various methods to parse untrusted XML data is known to be vulnerable to
XML attacks. Replace vulnerable imports with the equivalent defusedxml package.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B410 | import_lxml         | - lxml                             | Low       |

B411: import_xmlrpclib
----------------------

XMLRPC is particularly dangerous as it is also concerned with communicating
data over a network. Use defused.xmlrpc.monkey_patch() function to monkey-patch
xmlrpclib and mitigate remote XML attacks.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B411 | import_xmlrpclib    | - xmlrpclib                        | High      |

B412: import_httpoxy
--------------------
httpoxy is a set of vulnerabilities that affect application code running in
CGI, or CGI-like environments. The use of CGI for web applications should be
avoided to prevent this class of attack. More details are available [here](https://httpoxy.org/).

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B412 | import_httpoxy      | - wsgiref.handlers.CGIHandler      | High      |
|      |                     | - twisted.web.twcgi.CGIScript      |           |

B413: import_pycrypto
---------------------
pycrypto library is known to have publicly disclosed [buffer overflow
vulnerability](https://github.com/dlitz/pycrypto/issues/176). It is no longer
actively maintained and has been deprecated in favor of pyca/cryptography
library.

| ID   |  Name               |  Imports                           |  Severity |
|------|---------------------|------------------------------------|-----------|
| B413 | import_pycrypto     | - Crypto.Cipher                    | High      |
|      |                     | - Crypto.Hash                      |           |
|      |                     | - Crypto.IO                        |           |
|      |                     | - Crypto.Protocol                  |           |
|      |                     | - Crypto.PublicKey                 |           |
|      |                     | - Crypto.Random                    |           |
|      |                     | - Crypto.Signature                 |           |
|      |                     | - Crypto.Util                      |           |


!!! Tip
    In general, you should follow some simple rules for using cryptography:

    - Do not invent your own cryptography, use existing algorithms and implementations.
    - When utilizing cryptographic hashing, signing, or encryption, strong cryptographic primitives must be used.
    - Use established, reputable libraries with active maintenance in preference to implementing your own algorithms.
    - Pay carefull attention to key management and distribution, this is generally a harder problem than algorithm selection and implementation.

Use of the following cryptographic elements is encouraged:

- SHA-256 is the preferred hashing algorithm.
- AES is the preferred general encryption algorithm, with 128, 192 or 256 bit key lengths.
- HMAC is the preferred signing construction, in conjunction with a preferred hashing algorithm.
- TLSv1.2 or TLSv1.1 are preferred for protecting data in transit between clients and web services, but they must be configured securely, certificate validity, expiry and revocation status must be checked.

While for some use cases it may seem appropriate to use a weaker cryptographic element, the options listed above are generally advised.

Usage of the following is strongly discouraged:

- MD5
- DES
- RC4
- SSLv2, SSLv3, TLSv1.0
